# Moby seccomp profile provenance

`moby-seccomp-host-no-aslr.json` is derived from the official Moby Profiles
default seccomp policy:

- Repository: `https://github.com/moby/profiles`
- Commit: `f9bc03ec19b2dc4c091449b08e88f85c0caa9f0b`
- Source: `seccomp/default.json`
- Upstream raw SHA-256: `536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74`
- Upstream canonical-JSON SHA-256: `9da637d2ab0a204fcbd91bd88f1be9e004a3acab61c571a9f5b8870e588a17d2`
- License: Apache License 2.0; see `MOBY-PROFILES-LICENSE`

The derived policy adds only four exact `personality(2)` arguments. They are
the upstream-permitted values `0`, `8`, `0x20000`, and `0x20008`, each with
Linux `ADDR_NO_RANDOMIZE` (`0x40000`) set: `0x40000`, `0x40008`, `0x60000`,
and `0x60008`. All other syscall, architecture, capability, and argument
rules—including the current AF_ALG socket restriction—remain unchanged.

When updating this profile, start from a current official Moby profile, review
all upstream security changes, update both hashes, and retain the structural
regression test which removes exactly the four pwnc additions and compares the
canonical document with the pinned upstream digest.
