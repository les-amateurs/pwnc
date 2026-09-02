#include "model.hpp"

#include <cassert>
#include <iostream>
#include <string>

using pwnc::viewer::IncomingMessage;
using pwnc::viewer::Json;
using pwnc::viewer::PeerIdentity;
using pwnc::viewer::ViewerModel;
using pwnc::viewer::semantic_diff;

namespace {

Json envelope(const std::string& type, Json body = Json::object()) {
    Json message = {
        {"protocol", "pwnc-runtime"},
        {"version", 1},
        {"type", type},
        {"session_id", "session-a"},
    };
    message.update(body);
    return message;
}

}  // namespace

int main() {
    ViewerModel model(2, 2);
    std::string error;
    const PeerIdentity peer{123, 1000, 1000};
    assert(!model.apply({envelope("event", {{"event", {{"sequence", 0}, {"kind", "early"}}}}), peer}, error));
    assert(model.apply({envelope("hello", {{"session", {{"id", "session-a"}, {"pid", 77}}}}), peer}, error));
    assert(model.sessions().at("session-a").connected);

    for (int sequence = 0; sequence < 3; ++sequence) {
        assert(model.apply({envelope("event", {{"event", {{"sequence", sequence}, {"kind", "stop"}}}}), peer}, error));
    }
    assert(model.sessions().at("session-a").events.size() == 2);
    assert(model.sessions().at("session-a").dropped_events == 1);

    const Json before = {
        {"sequence", 0},
        {"modules", Json::array({{{"id", "main"}, {"load_bias", 4096}}})},
        {"maps", Json::array()},
        {"threads", Json::array({{{"id", 1}, {"registers", {{"pc", 16}}}}})},
        {"marks", Json::array({{{"mark_id", "m1"}, {"display", "before"}}})},
        {"heap", {
            {"arenas", Json::array({{{"address", 8192}, {"top", 12288}}})},
            {"chunks", Json::array({{{"allocation_id", "2000:2100:0"}, {"state", "allocated"}}})},
        }},
        {"verifications", Json::array()},
    };
    Json after = before;
    after["sequence"] = 1;
    after["threads"][0]["registers"]["pc"] = 32;
    after["marks"][0]["display"] = "after";
    after["heap"]["chunks"][0]["state"] = "tcache";
    const Json difference = semantic_diff(before, after);
    assert(difference["threads"]["changed"].size() == 1);
    assert(difference["marks"]["changed"].size() == 1);
    assert(difference["heap_chunks"]["changed"].size() == 1);

    assert(model.apply({envelope("snapshot", {{"snapshot", before}}), peer}, error));
    assert(model.apply({envelope("snapshot", {{"snapshot", after}, {"diff_from_previous", difference}}), peer}, error));
    assert(model.snapshot_count() == 2);
    assert(model.sessions().at("session-a").snapshots.back().diff_from_previous == difference);
    assert(model.apply({envelope("snapshot", {{"snapshot", after}}), peer}, error));
    assert(model.snapshot_count() == 2);
    model.disconnected("session-a");
    assert(!model.sessions().at("session-a").connected);
    assert(model.to_json()["sessions"].size() == 1);

    Json bad = envelope("hello");
    bad["version"] = 99;
    assert(!model.apply({bad, peer}, error));
    assert(!error.empty());
    bad["version"] = "one";
    assert(!model.apply({bad, peer}, error));
    bad = envelope("hello", {{"session", {{"id", 7}}}});
    assert(!model.apply({bad, peer}, error));

    std::cout << "runtime viewer model tests passed\n";
    return 0;
}
