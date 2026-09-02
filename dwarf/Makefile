PYTHON ?= python3
CARGO ?= cargo
PREFIX ?= $(HOME)/.local
BINJA_PLUGIN_DIR ?= $(HOME)/.binaryninja/plugins/teemo
GDB_INSTALL_DIR ?= $(PREFIX)/share/pwnc-teemo/gdb

EMITTER_MANIFEST := emitter/Cargo.toml
EMITTER_DEBUG := emitter/target/debug/teemo-dwarf
EMITTER_RELEASE := emitter/target/release/teemo-dwarf
PLUGIN_MODULES := analysis.py artifacts.py canary_analysis.py commands.py discovery.py extract.py extractor.py format_analysis.py ir.py prepass.py type_export.py __init__.py

.PHONY: all emitter emitter-release test test-python test-rust test-binja install install-plugin install-gdb clean

all: emitter

emitter:
	$(CARGO) build --manifest-path $(EMITTER_MANIFEST)

emitter-release:
	$(CARGO) build --release --manifest-path $(EMITTER_MANIFEST)

test: test-rust test-python

test-rust:
	$(CARGO) test --manifest-path $(EMITTER_MANIFEST)

test-python: emitter
	$(PYTHON) -m unittest discover -s tests -v

test-binja:
	$(PYTHON) tests/run_binja_harness.py

install: install-plugin install-gdb

install-plugin: emitter-release
	install -d "$(BINJA_PLUGIN_DIR)/teemo" "$(BINJA_PLUGIN_DIR)/bin"
	install -m 0644 plugin/__init__.py plugin/plugin.json "$(BINJA_PLUGIN_DIR)"
	install -m 0644 $(addprefix plugin/teemo/,$(PLUGIN_MODULES)) "$(BINJA_PLUGIN_DIR)/teemo"
	install -m 0755 "$(EMITTER_RELEASE)" "$(BINJA_PLUGIN_DIR)/bin/teemo-dwarf"

install-gdb:
	install -d "$(GDB_INSTALL_DIR)"
	install -m 0644 gdb/loader_core.py gdb/teemo_gdb.py "$(GDB_INSTALL_DIR)"

clean:
	$(CARGO) clean --manifest-path $(EMITTER_MANIFEST)
