#pragma once

#include "model.hpp"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace pwnc::viewer {

class IncomingQueue {
  public:
    explicit IncomingQueue(std::size_t limit = 512);

    bool push(IncomingMessage message);
    std::vector<IncomingMessage> drain();
    std::vector<IncomingMessage> wait_and_drain();
    void close();

    [[nodiscard]] std::size_t dropped() const;

  private:
    std::size_t limit_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<IncomingMessage> messages_;
    bool closed_{false};
    std::size_t dropped_{0};
};

class SocketServer {
  public:
    using WakeCallback = std::function<void()>;

    SocketServer(std::string socket_path, IncomingQueue& incoming, WakeCallback wake, int ready_fd = -1);
    ~SocketServer();

    SocketServer(const SocketServer&) = delete;
    SocketServer& operator=(const SocketServer&) = delete;

    void start();
    void stop();

    [[nodiscard]] const std::string& socket_path() const noexcept;
    [[nodiscard]] std::size_t parse_errors() const noexcept;

  private:
    void run();
    void accept_ready();
    void client_ready(int descriptor, short events);
    void close_client(int descriptor, bool publish_disconnect);
    void publish(IncomingMessage message);
    void setup_listener();
    void signal_ready();
    void unlink_owned_socket() noexcept;

    struct Client;

    std::string socket_path_;
    IncomingQueue& incoming_;
    WakeCallback wake_;
    int ready_fd_;
    int listener_{-1};
    int wake_read_{-1};
    int wake_write_{-1};
    std::uint64_t socket_device_{0};
    std::uint64_t socket_inode_{0};
    std::map<int, Client> clients_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<std::size_t> parse_errors_{0};
};

}  // namespace pwnc::viewer
