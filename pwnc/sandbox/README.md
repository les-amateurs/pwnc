# Local challenge sandboxes

The sandbox manager runs Docker challenges as the invoking host UID/GID,
publishes configured services only on loopback, and removes the route to
external networks by default. It is a persistent, project-scoped process: clients find it from the
path and seed in the nearest `pwnc.toml`, or from an explicit socket path.

The first release requires Linux with pidfd support, a local Docker daemon on
the same kernel, and Zig in `PATH`. The daemon must preserve the numeric host
UID/GID selected with `--user`; rootless or user-namespace-remapped setups that
map it to subordinate IDs fail closed during credential verification. Zig
builds the content-addressed static launch shim once; subsequent starts reuse
the private cached binary.

## Configure a challenge

```toml
[sandbox]
default-profile = "default"

[sandbox.default]
command = ["/challenge"]
stdio = "pipe"                 # "pipe", "pty", or "none"
pause-at-exec = true
allow-egress = false
read-only-root = false
# host-aslr = false             # optional; omitted leaves host ASLR unchanged

[sandbox.default.env]
FLAG_PATH = "/flag"

[sandbox.default.docker]
image = "local/challenge:latest"
pull = "never"

[[sandbox.default.ports]]
name = "pwn"
internal = 31337
protocol = "tcp"

[[sandbox.default.mounts]]
source = "./challenge"
target = "/challenge"
read-only = true
```

## QEMU user-mode profiles

The presence of a profile-local `qemu` table enables user-mode emulation for
that profile. `architecture` is required; every other QEMU setting has an
explicit default:

```toml
[sandbox.foreign]
command = ["/challenge"]
pause-at-exec = true            # wait on QEMU's GDB stub, not a host ptrace stop
host-aslr = false               # optional bool; omitted preserves host policy

[sandbox.foreign.docker]
image = "local/foreign-challenge:latest"

[sandbox.foreign.qemu]
architecture = "aarch64"
source = "auto"                # "auto", "host", or "image"; default "auto"
binary = "/usr/bin/qemu-aarch64" # optional source-specific path or name
sysroot = "/usr/aarch64-linux-gnu" # optional guest library prefix
guest-aslr = false              # optional bool; omitted preserves QEMU's default
```

`source = "image"` uses an emulator already in the image. An explicitly
configured `binary` must therefore be an absolute container path; when it is
omitted, the backend derives `qemu-ARCH` from `architecture` and resolves it
through the image's `PATH`. `source = "host"`
resolves an explicit host path or executable name and requires a statically
linked emulator suitable for a read-only bind mount. `source = "auto"` tries
an absolute or otherwise image-resolvable emulator first, then falls back to a
validated static host executable. `binary` and `sysroot` remain source-specific
strings rather than config-relative host paths so the backend can distinguish
image paths from host paths and executable names.

Both ASLR controls are tri-state. `true` and `false` request an explicit state;
omitting `host-aslr` or `guest-aslr` leaves the corresponding host or emulator
default unchanged. Existing `pause-at-exec` remains the only pause setting. On
a native profile it denotes the post-exec ptrace handoff; on a QEMU profile it
denotes a target waiting on its QEMU GDB stub.

`guest-aslr = false` selects a fixed, aligned QEMU guest reservation. Its
contract is guest-visible stability across launches for the PIE image, shared
libraries, heap, and stack; the addresses of QEMU itself and its host libraries
do not matter. `guest-aslr = true` chooses a fresh cryptographically random
reservation and should be understood as reservation-layout entropy rather than
a claim that QEMU reproduces every kernel ASLR rule. In particular,
qemu-i386's randomized reservations leave some low PIE/heap layouts fixed even
though fixed mode stabilizes all four mapping classes. qemu-x86_64 cannot use a
nonzero reservation around its fixed vsyscall page, so explicit `true` or
`false` is rejected instead of silently providing partial control; use the
upstream default by omitting `guest-aslr` there.

`host-aslr` independently controls the Linux personality inherited by the
native target or host QEMU process. It never changes the host-wide ASLR sysctl;
an explicit `true` fails if that sysctl has disabled randomization globally.
Docker's built-in seccomp profile rejects `ADDR_NO_RANDOMIZE`, so explicit
`false` selects the vendored, pinned Moby default profile with only the four
corresponding exact personality values added. The ordinary Docker profile is
left untouched for `true` and omitted values.

When a QEMU debug stub is available, snapshots include an additive `debug`
descriptor. Older snapshots without this member remain valid and deserialize
it as `None`:

```json
{
  "debug": {
    "transport": "tcp",
    "architecture": "aarch64",
    "emulator": "/usr/bin/qemu-aarch64",
    "host": "127.0.0.1",
    "port": 43137
  }
}
```

Paused QEMU profiles always publish this endpoint and remain stopped before
the first guest instruction. The host TCP listener is atomically reserved on
loopback and relayed to a private raw Unix QEMU stub after verifying the exact
QEMU PID and UID. Running profiles omit the stub: QEMU 7.1 through 9 always
suspend when `-g` is present, while the non-suspending `suspend=n` form is only
available in QEMU 10 and newer. This keeps the same configuration compatible
with the representative old and current QEMU lanes rather than unexpectedly
pausing older challenges.

`docker.image` and `docker.build` are mutually exclusive. Relative build,
Dockerfile, mount, and configured socket paths are resolved from `pwnc.toml`.
For egress-disabled TCP services, the manager atomically binds a loopback
listener and forwards only to the configured container port; the challenge
remains attached solely to a true Docker-internal network. Egress-enabled
profiles use Docker's atomic port publication. UDP publication on an internal
network is rejected in this first release instead of weakening isolation.

## Run and use the manager

Start the foreground manager in one process:

```console
$ pwnc sandbox manager
```

That process owns the containers, proxy sockets, stdio bridges, and optional
GDB pool, so it must remain alive. `SIGINT`, `SIGTERM`, project shutdown, and
normal process exit all trigger exact-ID cleanup.

An explicit rendezvous remains available when project discovery is unwanted:

```console
$ pwnc sandbox manager --socket /tmp/my-challenge.sock
$ pwnc sandbox check --socket /tmp/my-challenge.sock
```

Common challenge operations are:

```console
$ pwnc sandbox start
$ pwnc sandbox start --timeout 300
$ pwnc sandbox start --paused --pty debug -- /challenge --hard
$ pwnc sandbox start --profile default -- /alternate-challenge
$ pwnc sandbox list
$ pwnc sandbox show s-ID
$ pwnc sandbox stdio s-ID
$ pwnc sandbox connect s-ID pwn
$ pwnc sandbox resume s-ID
$ pwnc sandbox signal s-ID TERM
$ pwnc sandbox wait s-ID
$ pwnc sandbox kill s-ID
$ pwnc sandbox stop s-ID              # "close" is an alias
$ pwnc sandbox shutdown
```

Sandbox options precede a positional profile. Everything after `--` is the
replacement target argv. Use `--profile NAME` when overriding the command for
the configured default profile. `--env KEY=VALUE` is repeatable. State-changing
and inspection commands accept `--json` for one-line machine-readable output.
Startup has no deadline by default because a first Docker image build may take
longer than the client's ordinary control-operation timeout. `--timeout SECONDS`
sets an explicit deadline for the client wait; it does not cancel startup in the
manager, so a timed-out operation may later appear in `sandbox list`. Waiting is
socket-driven and does not poll.

`kill` leaves the exited sandbox record available; `stop` closes and removes
its owned runtime resources. Disconnecting from `stdio` does not stop the
challenge, so another client can reconnect later.

## Prepared GDB integration

The manager can own a prepared GDB pool while a separate viewer discovers it
from the same project:

```console
$ pwnc sandbox manager --gdb-pool-size 4 --gdb-name default
$ pwnc gdb view --name default
$ pwnc sandbox attach s-ID
```

The viewer exits when its selected GDB exits. Add `--reconnect` to keep the same
viewer open and route it to the next warm GDB in the pool.

Normal GDB init files are sourced by default; pass `--no-gdb-init` to the
manager to disable them. Use `--gdb-path /path/to/gdb` to select the binary and
repeat `--gdb-execute COMMAND` to configure every pooled process before it can
be selected—for example, `--gdb-execute 'source /path/to/gef.py'`. The same
hook is available to Python callers as `run_manager(gdb_setup=configure)`.
`attach` uses the GDB currently selected by the viewer and does not resume a
challenge paused at exec. Its sysroot is set to `/proc/<target-pid>/root`
before attachment, so shared-library symbols come from the container rather
than a potentially different host libc.

For a paused QEMU profile, the same `pwnc sandbox attach s-ID` operation uses
GDB's remote connection instead of attaching to the host emulator PID. It
loads the guest executable through `/proc/<qemu-pid>/root`, maps an absolute
guest sysroot beneath that root (or a relative one beneath the exact QEMU
working directory), and connects to the snapshot's loopback endpoint. The
initial guest-stub handoff is one-shot; continue the guest with the selected
GDB rather than `pwnc sandbox resume` or a host `SIGCONT`.

## Isolation and debugger boundary

- Docker is the only backend in this first release. Targets always use the
  invoking host UID/GID; there is no root fallback.
- Egress-disabled profiles use a true internal Docker network with no default
  route. Published TCP services use fixed-destination proxies bound only to
  `127.0.0.1` or `::1`; they do not give the challenge an egress path.
- Docker internal bridges still expose their gateway address to members, so a
  challenge can reach host services deliberately listening on that bridge or
  on all host addresses. It cannot route through the bridge to other networks.
- A paused target is handed off at the post-exec boundary before its first
  instruction. Before it may even fork the target, the trusted shim blocks on
  a host handshake that verifies its kernel peer PID and every host-visible
  UID/GID field. The target then clears capabilities and enables
  `no_new_privs` before execution; the supervisor detaches before publishing
  the target PID. Remapped credentials therefore fail before challenge code or
  constructors can run, including for non-paused starts.
- Image entrypoints and health checks are disabled so image metadata cannot
  execute outside that handoff. Only the single manager control socket is
  mounted into the container, read-only; stdio and other runtime endpoints
  remain host-only.
- Containers, their anonymous volumes, session networks, built image IDs, and
  proxy listeners remain exact manager-owned resources until cleanup succeeds.
- Control and stdio clients verify the server's Unix `SO_PEERCRED` UID before
  exchanging data. There is no token or password; the private/unique socket
  path plus kernel same-UID identity is the rendezvous boundary.
- The ptrace handoff supports ordinary same-UID attachment under Yama scope 1.
  More restrictive host LSM/Yama policy is reported as a capability error.
- GDB attachment is a one-shot handoff for the original exec stop. Its retained
  pidfd identity is revalidated under the session lifecycle lock; resuming or
  signaling the target permanently revokes that handoff, and a later SIGSTOP
  does not recreate it.
- The manager reports control, PID, stdio, and port readiness. It does not poll
  for application-specific readiness such as a service beginning to listen.
- Under qemu-user, the published host PID is the emulator. The manager's QEMU
  attach path uses the guest GDB stub and never treats that PID as a native
  guest process.
