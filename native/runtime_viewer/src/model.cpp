#include "model.hpp"

#include <algorithm>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace pwnc::viewer {
namespace {

std::optional<std::string> required_text(const Json& object, const char* key) {
    const auto iterator = object.find(key);
    if (iterator == object.end() || !iterator->is_string() || iterator->get_ref<const std::string&>().empty()) {
        return std::nullopt;
    }
    return iterator->get<std::string>();
}

Json indexed(const Json& values, const char* key) {
    Json result = Json::object();
    if (!values.is_array()) {
        return result;
    }
    for (const auto& value : values) {
        if (!value.is_object()) {
            continue;
        }
        const auto iterator = value.find(key);
        if (iterator == value.end() || (!iterator->is_string() && !iterator->is_number_integer())) {
            continue;
        }
        const auto identity = iterator->is_string() ? iterator->get<std::string>() : std::to_string(iterator->get<long long>());
        result[identity] = value;
    }
    return result;
}

Json keyed_diff(const Json& before, const Json& after, const char* key) {
    const Json left = indexed(before, key);
    const Json right = indexed(after, key);
    Json result = {{"added", Json::array()}, {"removed", Json::array()}, {"changed", Json::array()}};
    for (const auto& [identity, value] : right.items()) {
        const auto previous = left.find(identity);
        if (previous == left.end()) {
            result["added"].push_back(value);
        } else if (*previous != value) {
            result["changed"].push_back({{"id", identity}, {"before", *previous}, {"after", value}});
        }
    }
    for (const auto& [identity, value] : left.items()) {
        if (!right.contains(identity)) {
            result["removed"].push_back(value);
        }
    }
    return result;
}

Json maps_indexed(const Json& values) {
    Json result = Json::object();
    if (!values.is_array()) {
        return result;
    }
    for (const auto& value : values) {
        if (!value.is_object()) {
            continue;
        }
        std::ostringstream key;
        key << value.value("start", 0ULL) << ':' << value.value("end", 0ULL) << ':'
            << value.value("offset", 0ULL) << ':' << value.value("path", std::string{});
        result[key.str()] = value;
    }
    return result;
}

Json maps_diff(const Json& before, const Json& after) {
    const Json left = maps_indexed(before);
    const Json right = maps_indexed(after);
    Json result = {{"added", Json::array()}, {"removed", Json::array()}};
    for (const auto& [identity, value] : right.items()) {
        if (!left.contains(identity)) {
            result["added"].push_back(value);
        }
    }
    for (const auto& [identity, value] : left.items()) {
        if (!right.contains(identity)) {
            result["removed"].push_back(value);
        }
    }
    return result;
}

}  // namespace

ViewerModel::ViewerModel(const std::size_t snapshot_limit, const std::size_t event_limit)
    : snapshot_limit_(snapshot_limit), event_limit_(event_limit) {
    if (snapshot_limit_ == 0 || event_limit_ == 0) {
        throw std::invalid_argument("viewer model limits must be positive");
    }
}

bool ViewerModel::apply(const IncomingMessage& incoming, std::string& error) {
    const Json& message = incoming.document;
    if (!message.is_object()) {
        error = "message is not a JSON object";
        return false;
    }
    const auto protocol = required_text(message, "protocol");
    const auto version = message.find("version");
    if (!protocol || *protocol != kProtocolName || version == message.end() ||
        !version->is_number_integer() || *version != kProtocolVersion) {
        error = "unsupported runtime-viewer protocol";
        return false;
    }
    const auto type = required_text(message, "type");
    const auto session_id = required_text(message, "session_id");
    if (!type || !session_id) {
        error = "message lacks type or session_id";
        return false;
    }

    if (*type == "hello") {
        const auto iterator = message.find("session");
        if (iterator == message.end() || !iterator->is_object()) {
            error = "hello message lacks session metadata";
            return false;
        }
        const auto described_id = required_text(*iterator, "id");
        if (!described_id || *described_id != *session_id) {
            error = "hello session identity does not match its envelope";
            return false;
        }
        auto& session = sessions_[*session_id];
        session.id = *session_id;
        session.peer = incoming.peer;
        session.info = *iterator;
        session.connected = true;
        return true;
    }
    const auto session_iterator = sessions_.find(*session_id);
    if (session_iterator == sessions_.end()) {
        error = "session must send hello before runtime data";
        return false;
    }
    auto& session = session_iterator->second;
    session.peer = incoming.peer;
    if (*type == "event") {
        const auto iterator = message.find("event");
        if (iterator == message.end() || !iterator->is_object()) {
            error = "event message lacks event object";
            return false;
        }
        if (session.events.size() == event_limit_) {
            session.events.pop_front();
            ++session.dropped_events;
        }
        session.events.push_back(*iterator);
        return true;
    }
    if (*type == "snapshot") {
        const auto iterator = message.find("snapshot");
        if (iterator == message.end() || !iterator->is_object()) {
            error = "snapshot message lacks snapshot object";
            return false;
        }
        const auto sequence = iterator->find("sequence");
        if (sequence == iterator->end() || !sequence->is_number_integer()) {
            error = "snapshot lacks an integer sequence";
            return false;
        }
        const auto duplicate = std::find_if(
            session.snapshots.begin(), session.snapshots.end(), [&](const SnapshotRecord& record) {
                const auto previous = record.snapshot.find("sequence");
                return previous != record.snapshot.end() && *previous == *sequence;
            }
        );
        if (duplicate != session.snapshots.end()) {
            *duplicate = {*iterator, message.value("diff_from_previous", Json::object())};
            return true;
        }
        if (session.snapshots.size() == snapshot_limit_) {
            session.snapshots.pop_front();
            ++session.dropped_snapshots;
        }
        session.snapshots.push_back({*iterator, message.value("diff_from_previous", Json::object())});
        return true;
    }
    if (*type == "goodbye") {
        session.connected = false;
        return true;
    }
    error = "unknown message type: " + *type;
    return false;
}

void ViewerModel::disconnected(const std::string& session_id) {
    const auto iterator = sessions_.find(session_id);
    if (iterator != sessions_.end()) {
        iterator->second.connected = false;
    }
}

const std::map<std::string, SessionState>& ViewerModel::sessions() const noexcept {
    return sessions_;
}

std::size_t ViewerModel::snapshot_count() const noexcept {
    std::size_t count = 0;
    for (const auto& [identity, session] : sessions_) {
        static_cast<void>(identity);
        count += session.snapshots.size();
    }
    return count;
}

Json ViewerModel::to_json() const {
    Json sessions = Json::array();
    for (const auto& [identity, session] : sessions_) {
        Json events = Json::array();
        for (const auto& event : session.events) {
            events.push_back(event);
        }
        Json snapshots = Json::array();
        Json diffs = Json::array();
        for (const auto& snapshot : session.snapshots) {
            snapshots.push_back(snapshot.snapshot);
            diffs.push_back(snapshot.diff_from_previous);
        }
        sessions.push_back({
            {"id", identity},
            {"connected", session.connected},
            {"peer", {{"pid", session.peer.pid}, {"uid", session.peer.uid}, {"gid", session.peer.gid}}},
            {"info", session.info},
            {"events", std::move(events)},
            {"snapshots", std::move(snapshots)},
            {"diffs", std::move(diffs)},
            {"dropped_events", session.dropped_events},
            {"dropped_snapshots", session.dropped_snapshots},
        });
    }
    return {{"protocol", kProtocolName}, {"version", kProtocolVersion}, {"sessions", std::move(sessions)}};
}

Json semantic_diff(const Json& before, const Json& after) {
    const auto array = [](const Json& object, const char* key) -> Json {
        const auto iterator = object.find(key);
        return iterator != object.end() && iterator->is_array() ? *iterator : Json::array();
    };
    const auto object = [](const Json& parent, const char* key) -> Json {
        const auto iterator = parent.find(key);
        return iterator != parent.end() && iterator->is_object() ? *iterator : Json::object();
    };
    const Json before_heap = object(before, "heap");
    const Json after_heap = object(after, "heap");
    return {
        {"before_sequence", before.value("sequence", -1)},
        {"after_sequence", after.value("sequence", -1)},
        {"modules", keyed_diff(array(before, "modules"), array(after, "modules"), "id")},
        {"maps", maps_diff(array(before, "maps"), array(after, "maps"))},
        {"threads", keyed_diff(array(before, "threads"), array(after, "threads"), "id")},
        {"marks", keyed_diff(array(before, "marks"), array(after, "marks"), "mark_id")},
        {"heap_arenas", keyed_diff(array(before_heap, "arenas"), array(after_heap, "arenas"), "address")},
        {"heap_chunks", keyed_diff(array(before_heap, "chunks"), array(after_heap, "chunks"), "allocation_id")},
        {"verifications", keyed_diff(array(before, "verifications"), array(after, "verifications"), "sequence")},
    };
}

}  // namespace pwnc::viewer
