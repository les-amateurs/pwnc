#include "socket_server.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

namespace pwnc::viewer {
namespace {

std::runtime_error system_error(const std::string& operation) {
    return std::runtime_error(operation + ": " + std::strerror(errno));
}

bool is_event_message(const IncomingMessage& message) {
    return message.document.is_object() && message.document.value("type", std::string{}) == "event";
}

bool is_snapshot_message(const IncomingMessage& message) {
    return message.document.is_object() && message.document.value("type", std::string{}) == "snapshot";
}

bool is_control_message(const IncomingMessage& message) {
    if (!message.document.is_object()) {
        return false;
    }
    const std::string type = message.document.value("type", std::string{});
    return type == "hello" || type == "goodbye";
}

void close_descriptor(int& descriptor) noexcept {
    if (descriptor >= 0) {
        while (::close(descriptor) < 0 && errno == EINTR) {
        }
        descriptor = -1;
    }
}

void write_byte(const int descriptor, const char value) {
    for (;;) {
        const auto result = ::write(descriptor, &value, 1);
        if (result == 1) {
            return;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        throw system_error("write readiness byte");
    }
}

}  // namespace

struct SocketServer::Client {
    PeerIdentity peer;
    std::string buffer;
    std::string session_id;
};

IncomingQueue::IncomingQueue(const std::size_t limit) : limit_(limit) {
    if (limit_ == 0) {
        throw std::invalid_argument("incoming queue limit must be positive");
    }
}

bool IncomingQueue::push(IncomingMessage message) {
    std::lock_guard lock(mutex_);
    if (closed_) {
        return false;
    }
    const bool wake = messages_.empty();
    if (messages_.size() == limit_) {
        if (is_event_message(message)) {
            ++dropped_;
            return false;
        }
        auto discard = std::find_if(messages_.begin(), messages_.end(), is_event_message);
        if (discard == messages_.end() && is_snapshot_message(message)) {
            discard = std::find_if(messages_.begin(), messages_.end(), is_snapshot_message);
        }
        if (discard == messages_.end() && is_control_message(message)) {
            discard = std::find_if(messages_.begin(), messages_.end(), is_snapshot_message);
        }
        if (discard == messages_.end() && is_control_message(message)) {
            const std::string incoming_type = message.document.value("type", std::string{});
            const std::string incoming_session = message.document.value("session_id", std::string{});
            discard = std::find_if(messages_.begin(), messages_.end(), [&](const IncomingMessage& queued) {
                return queued.document.is_object() &&
                       queued.document.value("type", std::string{}) == incoming_type &&
                       queued.document.value("session_id", std::string{}) == incoming_session;
            });
        }
        if (discard == messages_.end()) {
            ++dropped_;
            return false;
        }
        messages_.erase(discard);
        ++dropped_;
    }
    messages_.push_back(std::move(message));
    condition_.notify_one();
    return wake;
}

std::vector<IncomingMessage> IncomingQueue::drain() {
    std::lock_guard lock(mutex_);
    std::vector<IncomingMessage> result;
    result.reserve(messages_.size());
    while (!messages_.empty()) {
        result.push_back(std::move(messages_.front()));
        messages_.pop_front();
    }
    return result;
}

std::vector<IncomingMessage> IncomingQueue::wait_and_drain() {
    std::unique_lock lock(mutex_);
    condition_.wait(lock, [this] { return closed_ || !messages_.empty(); });
    std::vector<IncomingMessage> result;
    result.reserve(messages_.size());
    while (!messages_.empty()) {
        result.push_back(std::move(messages_.front()));
        messages_.pop_front();
    }
    return result;
}

void IncomingQueue::close() {
    std::lock_guard lock(mutex_);
    closed_ = true;
    condition_.notify_all();
}

std::size_t IncomingQueue::dropped() const {
    std::lock_guard lock(mutex_);
    return dropped_;
}

SocketServer::SocketServer(std::string socket_path, IncomingQueue& incoming, WakeCallback wake, const int ready_fd)
    : socket_path_(std::move(socket_path)), incoming_(incoming), wake_(std::move(wake)), ready_fd_(ready_fd) {
    if (socket_path_.empty()) {
        throw std::invalid_argument("viewer socket path cannot be empty");
    }
}

SocketServer::~SocketServer() {
    stop();
}

void SocketServer::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        return;
    }
    try {
        setup_listener();
        signal_ready();
        thread_ = std::thread(&SocketServer::run, this);
    } catch (...) {
        running_.store(false);
        close_descriptor(listener_);
        close_descriptor(wake_read_);
        close_descriptor(wake_write_);
        close_descriptor(ready_fd_);
        unlink_owned_socket();
        throw;
    }
}

void SocketServer::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    if (wake_write_ >= 0) {
        const char byte = 'X';
        const auto ignored = ::write(wake_write_, &byte, 1);
        static_cast<void>(ignored);
    }
    if (thread_.joinable()) {
        thread_.join();
    }
    for (auto& [descriptor, client] : clients_) {
        static_cast<void>(client);
        int owned = descriptor;
        close_descriptor(owned);
    }
    clients_.clear();
    close_descriptor(listener_);
    close_descriptor(wake_read_);
    close_descriptor(wake_write_);
    close_descriptor(ready_fd_);
    unlink_owned_socket();
}

const std::string& SocketServer::socket_path() const noexcept {
    return socket_path_;
}

std::size_t SocketServer::parse_errors() const noexcept {
    return parse_errors_.load();
}

void SocketServer::setup_listener() {
    sockaddr_un address {};
    if (socket_path_.size() >= sizeof(address.sun_path)) {
        throw std::invalid_argument("viewer socket path is too long");
    }
    struct stat existing {};
    if (::lstat(socket_path_.c_str(), &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode) || existing.st_uid != ::getuid()) {
            throw std::runtime_error("refusing to replace a non-socket or foreign viewer path");
        }
        int probe = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (probe < 0) {
            throw system_error("create stale-socket probe");
        }
        address = {};
        address.sun_family = AF_UNIX;
        std::memcpy(address.sun_path, socket_path_.c_str(), socket_path_.size() + 1);
        const int result = ::connect(probe, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        const int connect_error = errno;
        close_descriptor(probe);
        if (result == 0) {
            throw std::runtime_error("another runtime viewer already owns this socket");
        }
        if (connect_error != ECONNREFUSED && connect_error != ENOENT) {
            errno = connect_error;
            throw system_error("probe existing viewer socket");
        }
        if (::unlink(socket_path_.c_str()) < 0 && errno != ENOENT) {
            throw system_error("remove stale viewer socket");
        }
    } else if (errno != ENOENT) {
        throw system_error("inspect viewer socket path");
    }

    listener_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener_ < 0) {
        throw system_error("create viewer socket");
    }
    address = {};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, socket_path_.c_str(), socket_path_.size() + 1);
    const mode_t previous_mask = ::umask(0077);
    const int bind_result = ::bind(listener_, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    const int bind_error = errno;
    ::umask(previous_mask);
    if (bind_result < 0) {
        errno = bind_error;
        throw system_error("bind viewer socket");
    }
    if (::chmod(socket_path_.c_str(), 0600) < 0) {
        throw system_error("protect viewer socket");
    }
    if (::listen(listener_, 32) < 0) {
        throw system_error("listen on viewer socket");
    }
    struct stat owned {};
    if (::lstat(socket_path_.c_str(), &owned) < 0) {
        throw system_error("stat bound viewer socket");
    }
    socket_device_ = static_cast<std::uint64_t>(owned.st_dev);
    socket_inode_ = static_cast<std::uint64_t>(owned.st_ino);

    int descriptors[2] = {-1, -1};
    if (::pipe2(descriptors, O_NONBLOCK | O_CLOEXEC) < 0) {
        throw system_error("create viewer wake pipe");
    }
    wake_read_ = descriptors[0];
    wake_write_ = descriptors[1];
}

void SocketServer::signal_ready() {
    if (ready_fd_ >= 0) {
        write_byte(ready_fd_, 'R');
        close_descriptor(ready_fd_);
    }
}

void SocketServer::run() {
    while (running_.load()) {
        std::vector<pollfd> descriptors;
        descriptors.reserve(2 + clients_.size());
        descriptors.push_back({listener_, POLLIN, 0});
        descriptors.push_back({wake_read_, POLLIN, 0});
        for (const auto& [descriptor, client] : clients_) {
            static_cast<void>(client);
            descriptors.push_back({descriptor, POLLIN, 0});
        }
        int result;
        do {
            result = ::poll(descriptors.data(), descriptors.size(), -1);
        } while (result < 0 && errno == EINTR);
        if (result < 0) {
            break;
        }
        if (descriptors[1].revents != 0) {
            char discard[64];
            while (::read(wake_read_, discard, sizeof(discard)) > 0) {
            }
            if (!running_.load()) {
                break;
            }
        }
        if ((descriptors[0].revents & POLLIN) != 0) {
            accept_ready();
        }
        for (std::size_t index = 2; index < descriptors.size(); ++index) {
            if (descriptors[index].revents != 0) {
                client_ready(descriptors[index].fd, descriptors[index].revents);
            }
        }
    }
}

void SocketServer::accept_ready() {
    for (;;) {
        const int descriptor = ::accept4(listener_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (descriptor < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            return;
        }
        ucred credentials {};
        socklen_t size = sizeof(credentials);
        if (::getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &size) < 0 ||
            credentials.uid != ::getuid()) {
            int rejected = descriptor;
            close_descriptor(rejected);
            continue;
        }
        clients_.emplace(
            descriptor,
            Client{PeerIdentity{credentials.pid, credentials.uid, credentials.gid}, std::string{}, std::string{}}
        );
    }
}

void SocketServer::client_ready(const int descriptor, const short events) {
    auto client_iterator = clients_.find(descriptor);
    if (client_iterator == clients_.end()) {
        return;
    }
    if ((events & (POLLERR | POLLHUP | POLLNVAL)) != 0 && (events & POLLIN) == 0) {
        close_client(descriptor, true);
        return;
    }
    char bytes[64 * 1024];
    for (;;) {
        const auto count = ::recv(descriptor, bytes, sizeof(bytes), 0);
        if (count == 0) {
            close_client(descriptor, true);
            return;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            close_client(descriptor, true);
            return;
        }
        auto& client = client_iterator->second;
        client.buffer.append(bytes, static_cast<std::size_t>(count));
        if (client.buffer.size() > kMaximumMessageBytes) {
            close_client(descriptor, true);
            return;
        }
        for (;;) {
            const auto newline = client.buffer.find('\n');
            if (newline == std::string::npos) {
                break;
            }
            std::string line = client.buffer.substr(0, newline);
            client.buffer.erase(0, newline + 1);
            if (line.empty()) {
                continue;
            }
            try {
                Json document = Json::parse(line);
                bool admitted = false;
                if (document.is_object()) {
                    const auto session = document.find("session_id");
                    const auto type = document.find("type");
                    if (session != document.end() && session->is_string() &&
                        type != document.end() && type->is_string()) {
                        const std::string identity = session->get<std::string>();
                        const std::string message_type = type->get<std::string>();
                        if (message_type == "hello" &&
                            (client.session_id.empty() || client.session_id == identity)) {
                            client.session_id = identity;
                            admitted = true;
                        } else if (!client.session_id.empty() && client.session_id == identity) {
                            admitted = true;
                        }
                    }
                }
                if (admitted) {
                    publish({std::move(document), client.peer});
                } else {
                    ++parse_errors_;
                }
            } catch (const Json::exception&) {
                ++parse_errors_;
            }
        }
    }
}

void SocketServer::close_client(const int descriptor, const bool publish_disconnect) {
    const auto iterator = clients_.find(descriptor);
    if (iterator == clients_.end()) {
        return;
    }
    const std::string session_id = iterator->second.session_id;
    const PeerIdentity peer = iterator->second.peer;
    const bool replacement_connected = !session_id.empty() && std::any_of(
        clients_.begin(), clients_.end(), [&](const auto& entry) {
            return entry.first != descriptor && entry.second.session_id == session_id;
        }
    );
    int owned = descriptor;
    close_descriptor(owned);
    clients_.erase(iterator);
    if (publish_disconnect && !session_id.empty() && !replacement_connected) {
        publish({
            {{"protocol", kProtocolName},
             {"version", kProtocolVersion},
             {"type", "goodbye"},
             {"session_id", session_id}},
            peer,
        });
    }
}

void SocketServer::publish(IncomingMessage message) {
    if (incoming_.push(std::move(message)) && wake_) {
        wake_();
    }
}

void SocketServer::unlink_owned_socket() noexcept {
    if (socket_inode_ == 0) {
        return;
    }
    struct stat current {};
    if (::lstat(socket_path_.c_str(), &current) == 0 &&
        static_cast<std::uint64_t>(current.st_dev) == socket_device_ &&
        static_cast<std::uint64_t>(current.st_ino) == socket_inode_ && S_ISSOCK(current.st_mode)) {
        ::unlink(socket_path_.c_str());
    }
    socket_device_ = 0;
    socket_inode_ = 0;
}

}  // namespace pwnc::viewer
