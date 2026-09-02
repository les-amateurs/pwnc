# GDB DAP callback version matrix

Run on 2026-08-02 on the x86-64 Ubuntu host with Python 3.12.3.  Every
reported version below was executed; version strings are from the listed
binaries, not inferred from source trees or package metadata.

## Binaries and sources

| GDB | Executed binary | Source | SHA-256 |
| --- | --- | --- | --- |
| 14.2 | `/tmp/pwnc-gdb-version-matrix/install/14.2/bin/gdb` | [gdb-14.2.tar.xz](https://ftp.gnu.org/gnu/gdb/gdb-14.2.tar.xz) | `2d4dd8061d8ded12b6c63f55e45344881e8226105f4d2a9b234040efa5ce7772` |
| 15.1 | `/usr/bin/gdb` (`GNU gdb (Ubuntu 15.1-1ubuntu1~24.04.1) 15.1`) | Ubuntu host package | n/a |
| 16.3 | `/tmp/pwnc-gdb-version-matrix/install/16.3/bin/gdb` | [gdb-16.3.tar.xz](https://ftp.gnu.org/gnu/gdb/gdb-16.3.tar.xz) | `bcfcd095528a987917acf9fff3f1672181694926cc18d609c99d0042c00224c5` |
| 17.2 | `/tmp/pwnc-gdb-version-matrix/install/17.2/bin/gdb` | [gdb-17.2.tar.xz](https://ftp.gnu.org/gnu/gdb/gdb-17.2.tar.xz) | `1c036c0d72e4b3d1fb5c94c88632add6f9d76f4d7c4d2ea793c12a9f19a3228c` |

The GDB-side live RPC extension uses only the common
`request(..., on_dap_thread=True)`, `send_event`, and `gdb.post_event` carrier.
Each installed source build successfully imported `gdb.dap.server` before the
matrix was run.

## Reproducing the source builds

The host had the MPFR runtime but not its headers.  The development package
was extracted into the temporary matrix root without installing it globally:

```sh
mkdir -p /tmp/pwnc-gdb-version-matrix/deps/debs \
  /tmp/pwnc-gdb-version-matrix/deps/root \
  /tmp/pwnc-gdb-version-matrix/deps/mpfr
cd /tmp/pwnc-gdb-version-matrix/deps/debs
apt-get download libmpfr-dev
dpkg-deb -x ./libmpfr-dev_*.deb /tmp/pwnc-gdb-version-matrix/deps/root
ln -s /tmp/pwnc-gdb-version-matrix/deps/root/usr/include \
  /tmp/pwnc-gdb-version-matrix/deps/mpfr/include
ln -s /tmp/pwnc-gdb-version-matrix/deps/root/usr/lib/x86_64-linux-gnu \
  /tmp/pwnc-gdb-version-matrix/deps/mpfr/lib
```

For each `VERSION` in `14.2 16.3 17.2`:

```sh
curl -fL -o /tmp/pwnc-gdb-version-matrix/src/gdb-$VERSION.tar.xz \
  https://ftp.gnu.org/gnu/gdb/gdb-$VERSION.tar.xz
tar -C /tmp/pwnc-gdb-version-matrix/src \
  -xf /tmp/pwnc-gdb-version-matrix/src/gdb-$VERSION.tar.xz
mkdir -p /tmp/pwnc-gdb-version-matrix/build/$VERSION-final
cd /tmp/pwnc-gdb-version-matrix/build/$VERSION-final
/tmp/pwnc-gdb-version-matrix/src/gdb-$VERSION/configure \
  --prefix=/tmp/pwnc-gdb-version-matrix/install/$VERSION \
  --with-python=/usr/bin/python3 \
  --with-expat \
  --with-mpfr=/tmp/pwnc-gdb-version-matrix/deps/mpfr \
  --without-guile \
  --without-debuginfod \
  --without-libunwind-ia64 \
  --without-intel-pt \
  --disable-werror \
  --disable-nls \
  --disable-binutils \
  --disable-ld \
  --disable-gold \
  --disable-gas \
  --disable-gprof \
  --disable-gprofng \
  --disable-sim
make -j5 all-gdb
make install-gdb
```

The builds use GDB's bundled readline.  The exact successful invocations are
also recorded in `/tmp/pwnc-gdb-version-matrix/build/VERSION-final/config.log`.

## Commands and results

`GDB_PATH` was replaced with each exact binary path from the table:

```sh
timeout --signal=KILL 45s python3 \
  tests/dap/experiments/rpc_probe.py --gdb GDB_PATH --depth 32

timeout --signal=KILL 45s python3 \
  tests/dap/experiments/execute_intercept_driver.py \
  --gdb GDB_PATH --mode both --json

timeout --signal=KILL 45s python3 \
  tests/dap/experiments/rpc_gef_probe.py \
  --gdb GDB_PATH --gef /home/ctf/bata24-gef/gef.py --depth 2

timeout --signal=KILL 45s python3 \
  tests/dap/experiments/rpc_gef_probe.py \
  --gdb GDB_PATH --gef /home/ctf/bata24-gef/gef.py --depth 1 \
  --inject-before-plugin

timeout --signal=KILL 45s python3 -c \
  'from tests.dap.experiments.active_plugin_block_test import test_active_sync_plugin_blocks_recursive_gdb_work as run; run("GDB_PATH"); print("PASS active unmodified-GEF boundary probe")'
```

| GDB | Core RPC, depth 32 | `gdb.execute`, batch + DAP | GEF in callbacks, depth 2 | Active sync GEF boundary |
| --- | --- | --- | --- | --- |
| 14.2 | PASS | PASS | PASS | PASS: blocking boundary reproduced |
| 15.1 | PASS | PASS | PASS | PASS: blocking boundary reproduced |
| 16.3 | PASS | PASS | PASS | PASS: blocking boundary reproduced |
| 17.2 | PASS | PASS | PASS | PASS: blocking boundary reproduced |

The runtime wrapper was also installed *before* sourcing GEF on every listed
version.  All four preload-injection runs passed.  This is the ordering needed
for plugins that capture `gdb.execute` while loading; a reference captured
before injection necessarily continues to call the original C function, as the
synthetic interception probe demonstrates.

Every depth-32 core run completed 33 recursively nested operations using 33
synchronous callback workers.  It recorded 627 GDB-side trace entries, kept
all GDB API and synchronous plugin work on one GDB main thread, kept DAP work
on a distinct DAP thread, and cleaned up all callback workers.  The generic
interception probe passed through both batch GDB and the real DAP interpreter.

The GEF fixture remained byte-for-byte unchanged, with SHA-256
`f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01`.
At depth 2, each integrated run completed three recursive operations and three
ordinary synchronous GEF `history` invocations.  Each invocation made nested
`gdb.execute("show commands ...")` calls on the GDB main thread.

The active-boundary PASS is a successful negative test, not proof that an
arbitrary live synchronous plugin frame can be suspended.  It pauses inside
unmodified GEF's already-active `HistoryCommand.invoke`, submits nested DAP GDB
work, and proves that the nested work remains pending until the plugin's
one-second fuse lets that stack return.  AST-lowering our own operation frame
therefore permits recursive callbacks around synchronous plugin calls, but it
does not create a continuation inside an arbitrary already-running plugin.

## Extended robustness and live-inferior matrix

The same four binaries were subsequently exercised with the reader-isolated
transport, cooperative cancellation/admission matrix, and a real native
inferior stopped after a heap allocation:

```sh
timeout --signal=KILL 150s python3 \
  tests/dap/experiments/rpc_failure_matrix.py \
  --gdb GDB_PATH --require-gef

timeout --signal=KILL 150s python3 \
  tests/dap/experiments/routed_transport_probe.py \
  --gdb GDB_PATH --require-gef --depth 8

timeout --signal=KILL 150s python3 \
  tests/dap/experiments/gef_live_inferior_probe.py \
  --gdb GDB_PATH --gef /home/ctf/bata24-gef/gef.py --depth 1
```

| GDB | Awaited cancel + callback caps | Reader-isolated transport, depth 8 | Live-inferior GEF commands |
| --- | --- | --- | --- |
| 14.2 | PASS | PASS | PASS |
| 15.1 | PASS | PASS | PASS |
| 16.3 | PASS | PASS | PASS |
| 17.2 | PASS | PASS | PASS |

For each GDB, cancellation remained non-terminal while two separately gated
host cleanup effects ran, then became `CANCELLED` only after both replies had
resumed the lowered `finally`.  The depth and global-active limits rejected
overflow before constructing a callback thread, did not starve DAP replies,
and admitted a recovery callback after capacity was released.

The transport probe kept its byte-reader to framing and queue insertion.  A
separate router owned JSON decoding, response correlation, timeout/late/close
selection, and condition-slot completion; arbitrary event and completion
callbacks ran on dynamically admitted worker threads.  Untouched GEF completed
nine recursively nested callback operations at depth eight on every version.

The native-inferior probe compiled an x86-64 fixture, stopped at a real
breakpoint after `malloc`, and synchronously invoked `gef version`, `checksec`,
`vmmap`, `xinfo`, `got`, `context`, and `heap chunks` from a host callback.
Every command produced observable output.  Runtime-only injection additionally
proved that untouched `ContextCommand` nested its `context-regs`,
`context-stack`, and `context-code` `gdb.execute` calls within the outer command
on GDB's main thread.  The GEF SHA-256 remained
`f370b1759b59ace61ced26a5491b596a2ca910bff1d657f4736130cd59c20b01`.

Raw core, interception, and GEF outputs, plus successful and failed build logs,
are retained under `/tmp/pwnc-gdb-version-matrix/`.  No downloaded or compiled
artifact is added to the repository.

## Setup failures

There were no callback, DAP, interception, or GEF runtime failures in the
matrix.  Two discarded build configurations failed before compilation:

- automatic dependency detection could not find `mpfr.h`;
- `--with-system-readline` could not find readline development headers.

The successful recipe above resolves the first through an extracted MPFR
prefix and the second by using GDB's bundled readline.
