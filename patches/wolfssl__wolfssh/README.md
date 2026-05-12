# patches/wolfssl__wolfssh

## Patch: 0001-expose-resize-cb-setters-without-NO_FILESYSTEM.patch

**File patched:** `managed_components/wolfssl__wolfssh/src/ssh.c`

In wolfSSH up to at least 1.4.22, three functions related to terminal resize
handling are compiled inside a single `#if defined(WOLFSSH_TERM) &&
!defined(NO_FILESYSTEM)` guard: `wolfSSH_ChangeTerminalSize`,
`wolfSSH_SetTerminalResizeCb`, and `wolfSSH_SetTerminalResizeCtx`. This
project defines `NO_FILESYSTEM` in `user_settings.h` -- a hard requirement
because wolfSSL cannot use POSIX filesystem APIs on the bare-metal ESP32-S3
environment. With `NO_FILESYSTEM` defined the entire block is compiled out,
yet `wolfssh/ssh.h` declares the two setter functions unconditionally,
producing an undefined-reference linker error.

The patch splits the closing `#endif` of `wolfSSH_ChangeTerminalSize` so that
only that function -- which sends resize requests through the SSH wire protocol
and has a genuine filesystem dependency in the upstream implementation -- stays
inside the `WOLFSSH_TERM && !NO_FILESYSTEM` guard. The two callback setters,
`wolfSSH_SetTerminalResizeCb` and `wolfSSH_SetTerminalResizeCtx`, move into a
plain `#if defined(WOLFSSH_TERM)` block immediately after. Their bodies do
nothing more than write into fields of the `WOLFSSH` struct and have no
filesystem operations, so the tighter guard is unnecessary for them.

The callback-setter pair is called from `main/ssh_server.c` at lines 404-405
after each successful `wolfSSH_accept`. `wolfSSH_SetTerminalResizeCb`
registers `term_resize_cb`, which translates incoming SSH window-change
requests into xterm CSI resize sequences injected into the USB-bound ring
buffer. `wolfSSH_SetTerminalResizeCtx` passes `s_ssh_to_usb` as the opaque
context pointer delivered to that callback. Without the patch, the linker
rejects the build because neither symbol exists in the compiled library.

**Version compatibility:** The patch was developed and verified against wolfSSH
1.4.20 (exact line match). It also applies cleanly to 1.4.22 with a 22-line
offset. Because `apply_managed_patches_cmake.py` calls `patch --dry-run -R`
before each application, an already-patched tree is skipped automatically on
incremental builds. If a future wolfSSH version refactors `src/ssh.c` such
that the patch context no longer matches, cmake configure will fail with an
error, prompting a review of the patch against the new upstream source.
