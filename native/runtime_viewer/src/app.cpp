#include "model.hpp"
#include "socket_server.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <SDL.h>
#include <SDL_opengl.h>
#include <imgui.h>
#include <imgui_impl_opengl3.h>
#include <imgui_impl_sdl2.h>
#include <unistd.h>

namespace pwnc::viewer {
namespace {

struct Options {
    std::string socket_path;
    int ready_fd{-1};
    bool headless{false};
    std::size_t exit_after_snapshots{0};
    std::size_t exit_after_frames{0};
    std::string model_output;
};

struct SnapshotSelection {
    int before{0};
    int after{0};
    int selected_mark{0};
    float heap_zoom{1.0F};
    float heap_pan{0.0F};
};

struct UiState {
    std::string selected_session;
    std::map<std::string, SnapshotSelection> selections;
};

std::string default_socket_path() {
    const char* configured = std::getenv("PWNC_RUNTIME_VIEWER_SOCKET");
    if (configured != nullptr && *configured != '\0') {
        return configured;
    }
    const char* runtime = std::getenv("XDG_RUNTIME_DIR");
    std::filesystem::path root = runtime != nullptr && *runtime != '\0' ? runtime : "/tmp";
    return (root / ("pwnc-runtime-viewer-" + std::to_string(::getuid()) + ".sock")).string();
}

std::size_t parse_size(const std::string& text, const char* option) {
    std::size_t consumed = 0;
    const auto value = std::stoull(text, &consumed, 10);
    if (consumed != text.size() || value > std::numeric_limits<std::size_t>::max()) {
        throw std::invalid_argument(std::string("invalid value for ") + option);
    }
    return static_cast<std::size_t>(value);
}

Options parse_options(const int argc, char** argv) {
    Options options;
    options.socket_path = default_socket_path();
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        const auto value = [&](const char* option) -> std::string {
            if (++index >= argc) {
                throw std::invalid_argument(std::string(option) + " requires a value");
            }
            return argv[index];
        };
        if (argument == "--socket") {
            options.socket_path = value("--socket");
        } else if (argument == "--ready-fd") {
            options.ready_fd = std::stoi(value("--ready-fd"));
        } else if (argument == "--headless") {
            options.headless = true;
        } else if (argument == "--exit-after-snapshots") {
            options.exit_after_snapshots = parse_size(value("--exit-after-snapshots"), "--exit-after-snapshots");
        } else if (argument == "--exit-after-frames") {
            options.exit_after_frames = parse_size(value("--exit-after-frames"), "--exit-after-frames");
        } else if (argument == "--model-out") {
            options.model_output = value("--model-out");
        } else if (argument == "--help") {
            std::cout
                << "usage: pwnc-runtime-viewer [--socket PATH] [--ready-fd FD]\n"
                   "                           [--headless --exit-after-snapshots N --model-out FILE]\n"
                   "                           [--exit-after-frames N]\n";
            std::exit(0);
        } else {
            throw std::invalid_argument("unknown option: " + argument);
        }
    }
    if (options.headless && options.exit_after_snapshots == 0) {
        throw std::invalid_argument("headless mode requires --exit-after-snapshots");
    }
    return options;
}

const Json& array_or_empty(const Json& object, const char* key) {
    static const Json empty = Json::array();
    if (!object.is_object()) {
        return empty;
    }
    const auto iterator = object.find(key);
    return iterator != object.end() && iterator->is_array() ? *iterator : empty;
}

std::string address_text(const Json& value) {
    if (value.is_null()) {
        return "-";
    }
    if (!value.is_number_unsigned() && !value.is_number_integer()) {
        return value.dump();
    }
    std::ostringstream stream;
    stream << "0x" << std::hex << value.get<std::uint64_t>();
    return stream.str();
}

std::string text_or(const Json& object, const char* key, const std::string& fallback = {}) {
    if (!object.is_object()) {
        return fallback;
    }
    const auto iterator = object.find(key);
    if (iterator == object.end() || iterator->is_null()) {
        return fallback;
    }
    return iterator->is_string() ? iterator->get<std::string>() : iterator->dump();
}

std::string short_session_label(const SessionState& session) {
    std::string label;
    const auto main = session.info.find("main");
    if (main != session.info.end() && main->is_object()) {
        const std::string path = text_or(*main, "path");
        if (!path.empty()) {
            label = std::filesystem::path(path).filename().string();
        }
    }
    if (label.empty()) {
        label = "session " + session.id.substr(0, std::min<std::size_t>(8, session.id.size()));
    }
    return (session.connected ? "● " : "○ ") + label;
}

void table_value(const Json& value) {
    const std::string display = value.is_string() ? value.get<std::string>() : value.dump();
    ImGui::TextUnformatted(display.c_str());
}

void draw_modules(const Json& snapshot) {
    const Json& modules = array_or_empty(snapshot, "modules");
    ImGui::Text("%zu loaded images", modules.size());
    if (!ImGui::BeginTable("modules", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        return;
    }
    ImGui::TableSetupColumn("Kind");
    ImGui::TableSetupColumn("Name");
    ImGui::TableSetupColumn("Load bias");
    ImGui::TableSetupColumn("Build ID");
    ImGui::TableSetupColumn("Path");
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(modules.size()));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& module = modules.at(static_cast<std::size_t>(row));
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(module, "kind", "unknown").c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(module, "name").c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(address_text(module.value("load_bias", Json())).c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(module, "build_id", "-").c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(module, "path", "-").c_str());
        }
    }
    ImGui::EndTable();
}

void draw_maps(const Json& snapshot) {
    const Json& maps = array_or_empty(snapshot, "maps");
    if (!ImGui::BeginTable("maps", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        return;
    }
    for (const char* title : {"Start", "End", "Perms", "Offset", "Path"}) {
        ImGui::TableSetupColumn(title);
    }
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(maps.size()));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& mapping = maps.at(static_cast<std::size_t>(row));
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(address_text(mapping.value("start", Json())).c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(address_text(mapping.value("end", Json())).c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(mapping, "permissions", "---").c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(address_text(mapping.value("offset", Json())).c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(mapping, "path").c_str());
        }
    }
    ImGui::EndTable();
}

void draw_variables(const Json& frame, const char* key) {
    const Json& variables = array_or_empty(frame, key);
    if (variables.empty()) {
        return;
    }
    ImGui::TextUnformatted(key);
    if (!ImGui::BeginTable(key, 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        return;
    }
    for (const char* title : {"Name", "Type", "Value", "Address", "Scope"}) {
        ImGui::TableSetupColumn(title);
    }
    ImGui::TableHeadersRow();
    for (const auto& variable : variables) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(text_or(variable, "name").c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(text_or(variable, "type", "-").c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(text_or(variable, "value", variable.value("optimized_out", false) ? "<optimized out>" : "-").c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(address_text(variable.value("address", Json())).c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%d", variable.value("scope_depth", 0));
    }
    ImGui::EndTable();
}

void draw_threads(const Json& snapshot) {
    const Json& threads = array_or_empty(snapshot, "threads");
    for (const auto& thread : threads) {
        const int id = thread.value("id", -1);
        const std::string label = "Thread " + std::to_string(id) + "##thread-" + std::to_string(id);
        if (!ImGui::TreeNode(label.c_str())) {
            continue;
        }
        ImGui::Text("state: %s", text_or(thread, "state", "unknown").c_str());
        const auto registers = thread.find("registers");
        if (registers != thread.end() && registers->is_object() && ImGui::TreeNode("Registers")) {
            if (ImGui::BeginTable("register-values", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                int column = 0;
                for (const auto& [name, value] : registers->items()) {
                    if (column % 4 == 0) {
                        ImGui::TableNextRow();
                    }
                    ImGui::TableNextColumn();
                    ImGui::Text("%s = %s", name.c_str(), address_text(value).c_str());
                    ++column;
                }
                ImGui::EndTable();
            }
            ImGui::TreePop();
        }
        for (const auto& frame : array_or_empty(thread, "frames")) {
            std::ostringstream frame_label;
            frame_label << '#' << frame.value("level", -1) << ' ' << text_or(frame, "name", "?") << " @ "
                        << address_text(frame.value("pc", Json()));
            if (ImGui::TreeNode(frame_label.str().c_str())) {
                if (!text_or(frame, "source").empty()) {
                    ImGui::Text("%s:%d", text_or(frame, "source").c_str(), frame.value("line", 0));
                }
                draw_variables(frame, "arguments");
                draw_variables(frame, "locals");
                ImGui::TreePop();
            }
        }
        const auto libc = thread.find("libc");
        if (libc != thread.end() && libc->is_object() && ImGui::TreeNode("Per-thread libc facts")) {
            for (const auto& [name, value] : libc->items()) {
                ImGui::Text("%s: %s", name.c_str(), address_text(value).c_str());
            }
            ImGui::TreePop();
        }
        ImGui::TreePop();
    }
}

void draw_payload(const Json& payload) {
    if (!payload.is_object()) {
        return;
    }
    ImGui::Text("%s: %s", text_or(payload, "kind", "payload").c_str(), text_or(payload, "description").c_str());
    ImGui::Text("target: %s / %d-bit / %s", text_or(payload, "architecture", "?").c_str(), payload.value("bits", 0),
                text_or(payload, "endian", "?").c_str());
    const Json& spans = array_or_empty(payload, "spans");
    if (ImGui::BeginTable("payload-spans", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        for (const char* title : {"Offset", "Size", "Role", "Pointer", "Expression"}) {
            ImGui::TableSetupColumn(title);
        }
        ImGui::TableHeadersRow();
        for (const auto& span : spans) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("%#x", span.value("offset", 0));
            ImGui::TableNextColumn();
            ImGui::Text("%#x", span.value("size", 0));
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(span, "role").c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(span, "pointer_kind", "-").c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(span, "expression", "-").c_str());
        }
        ImGui::EndTable();
    }
}

int base64_value(const unsigned char character) {
    if (character >= 'A' && character <= 'Z') {
        return static_cast<int>(character - 'A');
    }
    if (character >= 'a' && character <= 'z') {
        return static_cast<int>(character - 'a') + 26;
    }
    if (character >= '0' && character <= '9') {
        return static_cast<int>(character - '0') + 52;
    }
    if (character == '+') {
        return 62;
    }
    if (character == '/') {
        return 63;
    }
    return -1;
}

std::vector<unsigned char> decode_base64(const std::string& encoded) {
    std::vector<unsigned char> result;
    result.reserve(encoded.size() * 3U / 4U);
    unsigned int accumulator = 0;
    int bits = 0;
    for (const unsigned char character : encoded) {
        if (character == '=') {
            break;
        }
        const int value = base64_value(character);
        if (value < 0) {
            return {};
        }
        accumulator = (accumulator << 6U) | static_cast<unsigned int>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<unsigned char>((accumulator >> static_cast<unsigned int>(bits)) & 0xffU));
        }
    }
    return result;
}

void draw_typed_fields(const Json& mark) {
    const Json& fields = array_or_empty(mark, "typed_fields");
    if (fields.empty()) {
        return;
    }
    ImGui::SeparatorText(("Typed fields — " + text_or(mark, "type", "value")).c_str());
    if (!ImGui::BeginTable(
            "typed-fields", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 220.0F))) {
        return;
    }
    for (const char* title : {"Path", "Type", "Offset", "Size", "Value", "Pointer"}) {
        ImGui::TableSetupColumn(title);
    }
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(fields.size()));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& field = fields.at(static_cast<std::size_t>(row));
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(field, "path").c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(field, "type").c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%#x", field.value("offset", 0));
            ImGui::TableNextColumn();
            ImGui::Text("%#x", field.value("size", 0));
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(field, "display").c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(address_text(field.value("pointer", Json())).c_str());
        }
    }
    ImGui::EndTable();
}

void draw_mark_bytes(const Json& mark) {
    if (text_or(mark, "encoding") != "base64") {
        return;
    }
    const std::string encoded = text_or(mark, "data");
    const std::vector<unsigned char> bytes = decode_base64(encoded);
    if (bytes.empty() && !encoded.empty()) {
        ImGui::TextUnformatted("The marked byte payload is not valid base64.");
        return;
    }
    ImGui::SeparatorText("Captured bytes");
    ImGui::BeginChild("mark-hexdump", ImVec2(0.0F, 190.0F), ImGuiChildFlags_Borders);
    const int row_count = static_cast<int>((bytes.size() + 15U) / 16U);
    ImGuiListClipper clipper;
    clipper.Begin(row_count);
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const std::size_t start = static_cast<std::size_t>(row) * 16U;
            const std::size_t end = std::min(start + 16U, bytes.size());
            std::ostringstream line;
            line << std::hex << std::setfill('0') << std::setw(8) << start << "  ";
            for (std::size_t index = start; index < start + 16U; ++index) {
                if (index < end) {
                    line << std::setw(2) << static_cast<unsigned int>(bytes[index]) << ' ';
                } else {
                    line << "   ";
                }
            }
            line << " |";
            for (std::size_t index = start; index < end; ++index) {
                const unsigned char value = bytes[index];
                line << static_cast<char>(value >= 32U && value <= 126U ? value : '.');
            }
            line << '|';
            ImGui::TextUnformatted(line.str().c_str());
        }
    }
    ImGui::EndChild();
}

void draw_marks(const Json& snapshot, SnapshotSelection& selection) {
    const Json& marks = array_or_empty(snapshot, "marks");
    if (marks.empty()) {
        ImGui::TextUnformatted("No marked ranges were captured.");
        return;
    }
    selection.selected_mark = std::clamp(selection.selected_mark, 0, static_cast<int>(marks.size()) - 1);
    if (ImGui::BeginTable("marks", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                          ImVec2(0.0F, 240.0F))) {
        for (const char* title : {"Label", "Kind", "Address", "Size", "Generation", "Value"}) {
            ImGui::TableSetupColumn(title);
        }
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(marks.size()));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& mark = marks.at(static_cast<std::size_t>(row));
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                const std::string selectable = text_or(mark, "label", "mark") + "##mark-" + std::to_string(row);
                if (ImGui::Selectable(selectable.c_str(), selection.selected_mark == row, ImGuiSelectableFlags_SpanAllColumns)) {
                    selection.selected_mark = row;
                }
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(text_or(mark, "kind", "memory").c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(address_text(mark.value("address", Json())).c_str());
                ImGui::TableNextColumn();
                ImGui::Text("%#x", mark.value("size", 0));
                ImGui::TableNextColumn();
                table_value(mark.value("allocation_generation", Json()));
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(text_or(mark, "display").c_str());
            }
        }
        ImGui::EndTable();
    }
    const Json& selected = marks.at(static_cast<std::size_t>(selection.selected_mark));
    ImGui::SeparatorText(text_or(selected, "label", "mark").c_str());
    if (!text_or(selected, "error").empty()) {
        ImGui::TextColored(ImVec4(1.0F, 0.35F, 0.35F, 1.0F), "%s", text_or(selected, "error").c_str());
    }
    if (!text_or(selected, "display").empty()) {
        ImGui::TextWrapped("%s", text_or(selected, "display").c_str());
    }
    draw_typed_fields(selected);
    draw_mark_bytes(selected);
    const auto payload = selected.find("payload");
    if (payload != selected.end() && payload->is_object()) {
        draw_payload(*payload);
    }
}

ImU32 chunk_color(const std::string& state) {
    if (state == "allocated") {
        return IM_COL32(64, 180, 110, 230);
    }
    if (state == "top") {
        return IM_COL32(90, 130, 230, 230);
    }
    if (state == "tcache") {
        return IM_COL32(235, 170, 55, 230);
    }
    if (state == "fastbin") {
        return IM_COL32(225, 105, 60, 230);
    }
    return IM_COL32(160, 100, 200, 230);
}

void draw_heap(const Json& snapshot, SnapshotSelection& selection) {
    const auto heap = snapshot.find("heap");
    if (heap == snapshot.end() || !heap->is_object()) {
        ImGui::TextUnformatted("Heap provider was not captured for this snapshot.");
        return;
    }
    const Json& chunks = array_or_empty(*heap, "chunks");
    const Json& arenas = array_or_empty(*heap, "arenas");
    ImGui::Text("%zu arenas, %zu tracked chunks", arenas.size(), chunks.size());
    if (chunks.empty()) {
        ImGui::TextUnformatted("Capture with heap=True and at least one heap-chunk mark to populate the canvas.");
        return;
    }
    std::uint64_t low = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t high = 0;
    for (const auto& chunk : chunks) {
        const auto base = chunk.value("base", std::uint64_t{0});
        const auto size = chunk.value("size", std::uint64_t{0});
        low = std::min(low, base);
        high = std::max(high, base + size);
    }
    const ImVec2 canvas_size(std::max(200.0F, ImGui::GetContentRegionAvail().x), 320.0F);
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("heap-canvas", canvas_size, ImGuiButtonFlags_MouseButtonMiddle);
    const bool hovered = ImGui::IsItemHovered();
    if (hovered && ImGui::GetIO().MouseWheel != 0.0F) {
        selection.heap_zoom = std::clamp(selection.heap_zoom * (1.0F + ImGui::GetIO().MouseWheel * 0.15F), 0.25F, 128.0F);
    }
    if (hovered && ImGui::IsMouseDragging(ImGuiMouseButton_Middle)) {
        selection.heap_pan += ImGui::GetIO().MouseDelta.x;
    }
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(origin, ImVec2(origin.x + canvas_size.x, origin.y + canvas_size.y), IM_COL32(22, 25, 31, 255));
    draw->PushClipRect(origin, ImVec2(origin.x + canvas_size.x, origin.y + canvas_size.y), true);
    const double extent = std::max<double>(1.0, static_cast<double>(high - low));
    const double pixels_per_byte = static_cast<double>(canvas_size.x) / extent * selection.heap_zoom;
    constexpr float row_height = 42.0F;
    int visible = 0;
    for (const auto& chunk : chunks) {
        const auto base = chunk.value("base", std::uint64_t{0});
        const auto size = chunk.value("size", std::uint64_t{0});
        const float x0 = origin.x + selection.heap_pan + static_cast<float>(static_cast<double>(base - low) * pixels_per_byte);
        const float x1 = x0 + std::max(1.0F, static_cast<float>(static_cast<double>(size) * pixels_per_byte));
        if (x1 < origin.x || x0 > origin.x + canvas_size.x) {
            continue;
        }
        const float y0 = origin.y + 14.0F + static_cast<float>(visible % 7) * row_height;
        const float y1 = y0 + 30.0F;
        const std::string state = text_or(chunk, "state", "unknown");
        draw->AddRectFilled(ImVec2(x0, y0), ImVec2(x1, y1), chunk_color(state), 3.0F);
        draw->AddRect(ImVec2(x0, y0), ImVec2(x1, y1), IM_COL32(240, 240, 240, 150), 3.0F);
        if (x1 - x0 > 48.0F) {
            std::ostringstream label;
            label << state << " 0x" << std::hex << base << " / 0x" << size;
            draw->AddText(ImVec2(x0 + 4.0F, y0 + 7.0F), IM_COL32_WHITE, label.str().c_str());
        }
        ++visible;
    }
    draw->PopClipRect();
    ImGui::Text("zoom %.2fx, visible chunks %d", selection.heap_zoom, visible);
}

void draw_verifications(const Json& snapshot) {
    const Json& values = array_or_empty(snapshot, "verifications");
    if (!ImGui::BeginTable("verifications", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        return;
    }
    for (const char* title : {"Result", "Kind", "Name", "Expected", "Observed"}) {
        ImGui::TableSetupColumn(title);
    }
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(values.size()));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto& value = values.at(static_cast<std::size_t>(row));
            const bool ok = value.value("ok", false);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextColored(ok ? ImVec4(0.35F, 0.9F, 0.5F, 1.0F) : ImVec4(1.0F, 0.3F, 0.3F, 1.0F),
                               "%s", ok ? "PASS" : "FAIL");
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(value, "kind").c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(text_or(value, "name").c_str());
            ImGui::TableNextColumn();
            table_value(value.value("expected", Json()));
            ImGui::TableNextColumn();
            table_value(value.value("actual", Json()));
        }
    }
    ImGui::EndTable();
}

void snapshot_combo(const char* label, const SessionState& session, int& selected) {
    if (session.snapshots.empty()) {
        return;
    }
    selected = std::clamp(selected, 0, static_cast<int>(session.snapshots.size()) - 1);
    const std::string preview = text_or(session.snapshots.at(static_cast<std::size_t>(selected)).snapshot, "name", "snapshot");
    if (ImGui::BeginCombo(label, preview.c_str())) {
        for (std::size_t index = 0; index < session.snapshots.size(); ++index) {
            const auto& snapshot = session.snapshots[index].snapshot;
            const bool active = selected == static_cast<int>(index);
            const std::string item = text_or(snapshot, "name", "snapshot") + "##" + label + std::to_string(index);
            if (ImGui::Selectable(item.c_str(), active)) {
                selected = static_cast<int>(index);
            }
            if (active) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }
}

void draw_diff(const SessionState& session, SnapshotSelection& selection) {
    if (session.snapshots.empty()) {
        ImGui::TextUnformatted("No snapshots.");
        return;
    }
    snapshot_combo("A", session, selection.before);
    ImGui::SameLine();
    snapshot_combo("B", session, selection.after);
    const Json difference = semantic_diff(
        session.snapshots.at(static_cast<std::size_t>(selection.before)).snapshot,
        session.snapshots.at(static_cast<std::size_t>(selection.after)).snapshot
    );
    for (const char* domain : {
             "modules", "maps", "threads", "marks", "heap_arenas", "heap_chunks", "verifications"
         }) {
        const auto value = difference.find(domain);
        if (value == difference.end() || !value->is_object()) {
            continue;
        }
        std::size_t changes = 0;
        for (const auto& [kind, entries] : value->items()) {
            static_cast<void>(kind);
            if (entries.is_array()) {
                changes += entries.size();
            }
        }
        if (ImGui::TreeNode(domain, "%s (%zu changes)", domain, changes)) {
            for (const auto& [kind, entries] : value->items()) {
                if (!entries.is_array() || entries.empty()) {
                    continue;
                }
                if (ImGui::TreeNode(kind.c_str(), "%s (%zu)", kind.c_str(), entries.size())) {
                    ImGuiListClipper clipper;
                    clipper.Begin(static_cast<int>(entries.size()));
                    while (clipper.Step()) {
                        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                            const std::string text = entries.at(static_cast<std::size_t>(row)).dump(2);
                            ImGui::TextWrapped("%s", text.c_str());
                            ImGui::Separator();
                        }
                    }
                    ImGui::TreePop();
                }
            }
            ImGui::TreePop();
        }
    }
}

void draw_timeline(const SessionState& session, SnapshotSelection& selection) {
    snapshot_combo("Selected snapshot", session, selection.after);
    ImGui::SeparatorText("Snapshots");
    ImGui::BeginChild("snapshot-timeline", ImVec2(0.0F, 180.0F), ImGuiChildFlags_Borders);
    ImGuiListClipper snapshots;
    snapshots.Begin(static_cast<int>(session.snapshots.size()));
    while (snapshots.Step()) {
        for (int row = snapshots.DisplayStart; row < snapshots.DisplayEnd; ++row) {
            const auto& snapshot = session.snapshots.at(static_cast<std::size_t>(row)).snapshot;
            const std::string label = text_or(snapshot, "name", "snapshot") + "##timeline-" + std::to_string(row);
            if (ImGui::Selectable(label.c_str(), selection.after == row)) {
                selection.after = row;
            }
        }
    }
    ImGui::EndChild();
    ImGui::SeparatorText("Events");
    ImGui::BeginChild("event-timeline", ImVec2(0.0F, 220.0F), ImGuiChildFlags_Borders);
    ImGuiListClipper events;
    events.Begin(static_cast<int>(session.events.size()));
    while (events.Step()) {
        for (int row = events.DisplayStart; row < events.DisplayEnd; ++row) {
            const auto& event = session.events.at(static_cast<std::size_t>(row));
            ImGui::Text("#%d  %s", event.value("sequence", row), text_or(event, "kind", "event").c_str());
        }
    }
    ImGui::EndChild();
}

void draw_session(const SessionState& session, SnapshotSelection& selection) {
    ImGui::Text("%s  pid %lld  peer %lld", session.connected ? "connected" : "disconnected",
                session.info.value("pid", -1LL), static_cast<long long>(session.peer.pid));
    ImGui::SameLine();
    ImGui::TextDisabled("dropped: %zu events, %zu snapshots", session.dropped_events, session.dropped_snapshots);
    if (session.snapshots.empty()) {
        ImGui::TextUnformatted("Waiting for the first runtime snapshot…");
        return;
    }
    selection.after = std::clamp(selection.after, 0, static_cast<int>(session.snapshots.size()) - 1);
    const Json& snapshot = session.snapshots.at(static_cast<std::size_t>(selection.after)).snapshot;
    if (ImGui::BeginTabBar("runtime-tabs")) {
        if (ImGui::BeginTabItem("Timeline")) {
            draw_timeline(session, selection);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Modules & maps")) {
            if (ImGui::CollapsingHeader("Modules", ImGuiTreeNodeFlags_DefaultOpen)) {
                draw_modules(snapshot);
            }
            if (ImGui::CollapsingHeader("Mappings")) {
                draw_maps(snapshot);
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Threads")) {
            draw_threads(snapshot);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Marked memory & payloads")) {
            draw_marks(snapshot, selection);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Heap canvas")) {
            draw_heap(snapshot, selection);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Verification")) {
            draw_verifications(snapshot);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("A/B diff")) {
            draw_diff(session, selection);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

void draw_ui(const ViewerModel& model, UiState& state) {
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::Begin("pwnc runtime inspector", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);
    const auto& sessions = model.sessions();
    if (state.selected_session.empty() && !sessions.empty()) {
        state.selected_session = sessions.begin()->first;
    }
    ImGui::BeginChild("sessions", ImVec2(230.0F, 0.0F), ImGuiChildFlags_Borders | ImGuiChildFlags_ResizeX);
    ImGui::SeparatorText("Runtime sessions");
    for (const auto& [identity, session] : sessions) {
        const std::string label = short_session_label(session) + "##" + identity;
        if (ImGui::Selectable(label.c_str(), state.selected_session == identity)) {
            state.selected_session = identity;
            auto& selection = state.selections[identity];
            if (!session.snapshots.empty()) {
                selection.after = static_cast<int>(session.snapshots.size()) - 1;
            }
        }
        ImGui::TextDisabled("%s", text_or(session.info, "architecture", "unknown").c_str());
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("runtime", ImVec2(0.0F, 0.0F), ImGuiChildFlags_Borders);
    const auto selected = sessions.find(state.selected_session);
    if (selected == sessions.end()) {
        ImGui::TextUnformatted("No runtime publisher is connected. Start one with g.viewer.connect() or g.viewer.open().");
    } else {
        draw_session(selected->second, state.selections[selected->first]);
    }
    ImGui::EndChild();
    ImGui::End();
}

void apply_messages(ViewerModel& model, std::vector<IncomingMessage> messages) {
    for (const auto& message : messages) {
        std::string error;
        if (!model.apply(message, error)) {
            std::cerr << "ignored runtime message: " << error << '\n';
        }
    }
}

int run_headless(const Options& options) {
    IncomingQueue incoming;
    ViewerModel model;
    SocketServer server(options.socket_path, incoming, {}, options.ready_fd);
    server.start();
    while (model.snapshot_count() < options.exit_after_snapshots) {
        apply_messages(model, incoming.wait_and_drain());
    }
    server.stop();
    const std::string serialized = model.to_json().dump(2);
    if (options.model_output.empty() || options.model_output == "-") {
        std::cout << serialized << '\n';
    } else {
        std::ofstream output(options.model_output, std::ios::binary | std::ios::trunc);
        if (!output) {
            throw std::runtime_error("cannot open model output: " + options.model_output);
        }
        output << serialized << '\n';
    }
    return 0;
}

int run_gui(const Options& options) {
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) {
        throw std::runtime_error(std::string("SDL initialization failed: ") + SDL_GetError());
    }
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);
    SDL_Window* window = SDL_CreateWindow(
        "pwnc runtime inspector",
        SDL_WINDOWPOS_CENTERED,
        SDL_WINDOWPOS_CENTERED,
        1500,
        900,
        SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI
    );
    if (window == nullptr) {
        SDL_Quit();
        throw std::runtime_error(std::string("window creation failed: ") + SDL_GetError());
    }
    SDL_GLContext context = SDL_GL_CreateContext(window);
    if (context == nullptr) {
        SDL_DestroyWindow(window);
        SDL_Quit();
        throw std::runtime_error(std::string("OpenGL context creation failed: ") + SDL_GetError());
    }
    SDL_GL_MakeCurrent(window, context);
    SDL_GL_SetSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;
    if (!ImGui_ImplSDL2_InitForOpenGL(window, context) || !ImGui_ImplOpenGL3_Init("#version 150")) {
        throw std::runtime_error("Dear ImGui backend initialization failed");
    }

    const Uint32 wake_event = SDL_RegisterEvents(1);
    if (wake_event == static_cast<Uint32>(-1)) {
        throw std::runtime_error("SDL could not allocate a runtime wake event");
    }
    IncomingQueue incoming;
    ViewerModel model;
    SocketServer server(
        options.socket_path,
        incoming,
        [wake_event] {
            SDL_Event event {};
            event.type = wake_event;
            SDL_PushEvent(&event);
        },
        options.ready_fd
    );
    server.start();
    SDL_Event initial {};
    initial.type = wake_event;
    SDL_PushEvent(&initial);

    UiState ui;
    bool running = true;
    std::size_t rendered_frames = 0;
    while (running) {
        SDL_Event event {};
        if (SDL_WaitEvent(&event) == 0) {
            throw std::runtime_error(std::string("SDL event wait failed: ") + SDL_GetError());
        }
        do {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT ||
                (event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_CLOSE &&
                 event.window.windowID == SDL_GetWindowID(window))) {
                running = false;
            }
        } while (SDL_PollEvent(&event) != 0);
        apply_messages(model, incoming.drain());
        if (!running) {
            break;
        }
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();
        draw_ui(model, ui);
        ImGui::Render();
        int width = 0;
        int height = 0;
        SDL_GL_GetDrawableSize(window, &width, &height);
        glViewport(0, 0, width, height);
        glClearColor(0.055F, 0.06F, 0.075F, 1.0F);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);
        ++rendered_frames;
        if (options.exit_after_frames != 0 && rendered_frames >= options.exit_after_frames) {
            running = false;
        }
    }

    server.stop();
    incoming.close();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DeleteContext(context);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}

}  // namespace
}  // namespace pwnc::viewer

int main(const int argc, char** argv) {
    try {
        const auto options = pwnc::viewer::parse_options(argc, argv);
        return options.headless ? pwnc::viewer::run_headless(options) : pwnc::viewer::run_gui(options);
    } catch (const std::exception& error) {
        std::cerr << "pwnc-runtime-viewer: " << error.what() << '\n';
        return 1;
    }
}
