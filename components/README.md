# components/ -- Local ESP-IDF Components

This directory holds hand-written ESP-IDF components that are part of the
project source tree. Currently there is one: `wolfssl/`, a bridge component
that makes the wolfSSL cryptography library available to the rest of the
firmware. See [`wolfssl/README.md`](wolfssl/README.md) for a full description
of how it works and why it exists.

This directory is distinct from two other library locations in the project.
`managed_components/` (gitignored) is populated at build time by the IDF
Component Manager and contains registry-fetched packages -- most importantly
`wolfssl__wolfssl` and `wolfssl__wolfssh`, which supply the actual wolfSSL and
wolfSSH source trees that the bridge component compiles. `lib/` contains
PlatformIO libraries written for this project that target both the native
(desktop unit-test) and ESP32-S3 (firmware) build environments; those are
not ESP-IDF components and are not registered with `idf_component_register`.

The `wolfssl/` component registers itself under the IDF component name
`wolfssl`, compiles wolfSSL's sources directly from `managed_components/`, and
exposes the headers needed by the SSH server -- working around a CMake
dependency-resolution limitation in the upstream wolfSSH component wrapper.
