CXX ?= c++
CC ?= cc
AR ?= ar

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD := $(ROOT)/build
DEPS := $(ROOT)/.deps
IMGUI := $(DEPS)/imgui
SDL := $(DEPS)/sdl2
SDL_PREFIX := $(DEPS)/sdl2-install
JSON := $(DEPS)/json
PREFIX ?= /usr/local
DESTDIR ?=

CPPFLAGS := -I$(ROOT)/src -I$(IMGUI) -I$(IMGUI)/backends -I$(JSON)/include
CXXFLAGS ?= -O2 -g
CXXFLAGS += -std=c++20 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -pthread
LDFLAGS += -pthread

LOCAL_SOURCES := \
	$(ROOT)/src/app.cpp \
	$(ROOT)/src/model.cpp \
	$(ROOT)/src/socket_server.cpp
IMGUI_SOURCES := \
	$(IMGUI)/imgui.cpp \
	$(IMGUI)/imgui_draw.cpp \
	$(IMGUI)/imgui_tables.cpp \
	$(IMGUI)/imgui_widgets.cpp \
	$(IMGUI)/backends/imgui_impl_sdl2.cpp \
	$(IMGUI)/backends/imgui_impl_opengl3.cpp
APP_OBJECTS := $(patsubst $(ROOT)/%.cpp,$(BUILD)/%.o,$(LOCAL_SOURCES)) \
	$(patsubst $(IMGUI)/%.cpp,$(BUILD)/imgui/%.o,$(IMGUI_SOURCES))

.PHONY: all deps test install clean distclean

all: $(BUILD)/pwnc-runtime-viewer

deps: $(DEPS)/.fetched $(SDL_PREFIX)/lib/libSDL2.a

$(DEPS)/.fetched: fetch_deps.sh deps.lock
	./fetch_deps.sh
	@touch $@

$(SDL_PREFIX)/lib/libSDL2.a: $(DEPS)/.fetched
	mkdir -p $(DEPS)/sdl2-build
	cd $(DEPS)/sdl2-build && $(SDL)/configure \
		--prefix=$(SDL_PREFIX) \
		--disable-shared --enable-static \
		--disable-audio --disable-joystick --disable-haptic --disable-sensor \
		--disable-power --disable-filesystem --disable-libudev
	$(MAKE) -C $(DEPS)/sdl2-build -j$${PWNC_VIEWER_JOBS:-2}
	$(MAKE) -C $(DEPS)/sdl2-build install

$(BUILD)/pwnc-runtime-viewer: $(APP_OBJECTS) $(SDL_PREFIX)/lib/libSDL2.a
	$(CXX) $(APP_OBJECTS) $(LDFLAGS) $$($(SDL_PREFIX)/bin/sdl2-config --static-libs) -lGL -o $@

$(BUILD)/src/%.o: $(ROOT)/src/%.cpp $(DEPS)/.fetched $(SDL_PREFIX)/lib/libSDL2.a
	mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $$($(SDL_PREFIX)/bin/sdl2-config --cflags) $(CXXFLAGS) -c $< -o $@

$(BUILD)/imgui/%.o: $(IMGUI)/%.cpp $(DEPS)/.fetched $(SDL_PREFIX)/lib/libSDL2.a
	mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $$($(SDL_PREFIX)/bin/sdl2-config --cflags) $(CXXFLAGS) -Wno-conversion -Wno-shadow -c $< -o $@

$(BUILD)/model-test: $(ROOT)/tests/model_test.cpp $(ROOT)/src/model.cpp $(DEPS)/.fetched
	mkdir -p $(BUILD)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(ROOT)/tests/model_test.cpp $(ROOT)/src/model.cpp -o $@

test: $(BUILD)/model-test
	$(BUILD)/model-test

install: $(BUILD)/pwnc-runtime-viewer
	install -Dm755 $(BUILD)/pwnc-runtime-viewer $(DESTDIR)$(PREFIX)/bin/pwnc-runtime-viewer
	install -Dm644 $(ROOT)/protocol-v1.schema.json $(DESTDIR)$(PREFIX)/share/pwnc-runtime-viewer/protocol-v1.schema.json
	install -Dm644 $(ROOT)/licenses/DEAR_IMGUI.txt $(DESTDIR)$(PREFIX)/share/pwnc-runtime-viewer/licenses/DEAR_IMGUI.txt
	install -Dm644 $(ROOT)/licenses/SDL2.txt $(DESTDIR)$(PREFIX)/share/pwnc-runtime-viewer/licenses/SDL2.txt
	install -Dm644 $(ROOT)/licenses/NLOHMANN_JSON.txt $(DESTDIR)$(PREFIX)/share/pwnc-runtime-viewer/licenses/NLOHMANN_JSON.txt

clean:
	rm -rf -- $(BUILD)

distclean: clean
	rm -rf -- $(DEPS)
