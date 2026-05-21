# scripts/gen_eap_certs_asm.py
#
# PlatformIO extra_scripts hook -- pre-generates the EAP-TLS certificate
# assembly files (.S) that ESP-IDF's EMBED_TXTFILES custom command would
# normally produce during a ninja build.
#
# Root cause of the "run pio run twice" problem:
#   PlatformIO reads the cmake codemodel, sees ca.pem.S / client.crt.S /
#   client.key.S marked as isGenerated sources, then tries to assemble them
#   directly via SCons -- but SCons never invokes the cmake custom command
#   that would generate those .S files (PlatformIO doesn't run ninja; it
#   replaces the ninja build with its own SCons graph).  The files don't
#   exist on a clean build, so SCons fails immediately.
#
# Fix: run data_file_embed_asm.cmake ourselves immediately (at script-eval
# time, before SCons evaluates the build graph) for each cert file whenever
# WIFI_USE_ENTERPRISE certs are present, mirroring what espidf.py does for
# x509_crt_bundle.S.  The .S files are written to BUILD_DIR so SCons finds
# them exactly where the cmake codemodel says they live.

import os
import subprocess

Import("env")

PROJECT_DIR = env.subst("$PROJECT_DIR")
CERT_DIR = os.path.join(PROJECT_DIR, "main", "certs")
BUILD_DIR = env.subst("$BUILD_DIR")
IDF_PATH = env.PioPlatform().get_package_dir("framework-espidf")
CMAKE_BIN = os.path.join(
    env.PioPlatform().get_package_dir("tool-cmake"), "bin", "cmake"
)
EMBED_SCRIPT = os.path.join(
    IDF_PATH, "tools", "cmake", "scripts", "data_file_embed_asm.cmake"
)

CERT_FILES = [
    ("ca.pem",     "ca.pem.S",     "TEXT"),
    ("client.crt", "client.crt.S", "TEXT"),
    ("client.key", "client.key.S", "TEXT"),
]

# SCEP server's TLS trust bundle.  Embedded conditionally (independent of the
# EAP-TLS cert triple); falls back to the firmware-bundled trust store when
# absent.
SCEP_CERT_FILES = [
    ("scep_ca.pem", "scep_ca.pem.S", "TEXT"),
]


def _all_certs_present():
    return all(
        os.path.isfile(os.path.join(CERT_DIR, name))
        for name, _, _ in CERT_FILES
    )


def _scep_cert_present():
    return all(
        os.path.isfile(os.path.join(CERT_DIR, name))
        for name, _, _ in SCEP_CERT_FILES
    )


def _generate_asm_for_files(file_list, src_dir, label):
    """
    Run data_file_embed_asm.cmake for each file that is missing its .S.
    Called at script-eval time so the .S files exist before SCons builds the
    compilation graph.
    """
    os.makedirs(BUILD_DIR, exist_ok=True)

    for data_name, asm_name, file_type in file_list:
        data_file = os.path.join(src_dir, data_name)
        source_file = os.path.join(BUILD_DIR, asm_name)

        # Regenerate if missing or stale.
        if (
            os.path.isfile(source_file)
            and os.path.getmtime(source_file) >= os.path.getmtime(data_file)
        ):
            continue

        print("esp-tty: generating assembly for %s: %s" % (label, asm_name))
        cmd = [
            CMAKE_BIN,
            "-DDATA_FILE=" + data_file,
            "-DSOURCE_FILE=" + source_file,
            "-DFILE_TYPE=" + file_type,
            "-P",
            EMBED_SCRIPT,
        ]
        ret = subprocess.call(cmd, cwd=BUILD_DIR)
        if ret != 0:
            import sys
            sys.stderr.write(
                "ERROR: gen_eap_certs_asm.py: cmake failed for %s (exit %d)\n"
                % (asm_name, ret)
            )
            env.Exit(1)


def _generate_cert_asm():
    if _all_certs_present():
        _generate_asm_for_files(CERT_FILES, CERT_DIR, "EAP-TLS cert")
    if _scep_cert_present():
        _generate_asm_for_files(SCEP_CERT_FILES, CERT_DIR, "SCEP CA bundle")


# Run immediately at script-evaluation time -- before SCons reads sources.
_generate_cert_asm()
