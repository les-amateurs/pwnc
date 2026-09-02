#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

namespace pwnc::viewer {

using Json = nlohmann::json;

inline constexpr const char* kProtocolName = "pwnc-runtime";
inline constexpr int kProtocolVersion = 1;
inline constexpr std::size_t kMaximumMessageBytes = 16U * 1024U * 1024U;

struct PeerIdentity {
    std::int64_t pid{-1};
    std::int64_t uid{-1};
    std::int64_t gid{-1};
};

struct IncomingMessage {
    Json document;
    PeerIdentity peer;
};

struct SnapshotRecord {
    Json snapshot;
    Json diff_from_previous;
};

struct SessionState {
    std::string id;
    Json info = Json::object();
    PeerIdentity peer;
    bool connected{false};
    std::deque<Json> events;
    std::deque<SnapshotRecord> snapshots;
    std::size_t dropped_events{0};
    std::size_t dropped_snapshots{0};
};

class ViewerModel {
  public:
    explicit ViewerModel(std::size_t snapshot_limit = 128, std::size_t event_limit = 4096);

    bool apply(const IncomingMessage& incoming, std::string& error);
    void disconnected(const std::string& session_id);

    [[nodiscard]] const std::map<std::string, SessionState>& sessions() const noexcept;
    [[nodiscard]] std::size_t snapshot_count() const noexcept;
    [[nodiscard]] Json to_json() const;

  private:
    std::size_t snapshot_limit_;
    std::size_t event_limit_;
    std::map<std::string, SessionState> sessions_;
};

[[nodiscard]] Json semantic_diff(const Json& before, const Json& after);

}  // namespace pwnc::viewer
