#!/usr/bin/env python3
"""
test/scripts/test_scep_proto_cleanup.py
-- Structural assertions that scep_build_pkimessage_pkcsreq cleans up on
   error.

The EnvelopedData (env_scratch) build block previously used the
return-on-error CHK() macro, which bypassed the function's `done:`
cleanup label and leaked the heap-allocated enc_csr (CSR ciphertext) and
enc_cek (the RSA-wrapped AES content-encryption key -- a secret that
should be wiped before release).

After the M3.A fix the env_scratch block uses ENC_CHK (not CHK_G) so
the macro names are unmistakably distinct:
  - ENC_CHK: env_scratch (EnvelopedData) build block only
  - CHK_G:   outer SignedData build block only

This test guards against regressing by:
  - asserting ENC_CHK is defined exactly once (env_scratch block) and
    CHK_G is defined exactly once (SignedData block);
  - asserting that the env_scratch block contains no naked CHK() or
    CHK_G() invocations -- only ENC_CHK();
  - asserting that `done:` frees enc_csr, enc_cek, env_scratch, and
    calls mbedtls_x509_crt_free(&ra_crt).

Runs in milliseconds with no build required.
"""

import os
import re

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
SCEP_C      = os.path.join(PROJECT_DIR, "lib", "scep_proto", "scep_proto.c")


def _read():
    with open(SCEP_C) as f:
        return f.read()


def test_chk_g_macro_defined_twice():
    """After M3.A: ENC_CHK for env_scratch block, CHK_G for SignedData block.
    ENC_CHK and CHK_G must each be defined exactly once."""
    src = _read()
    enc_chk_defs = re.findall(r"#define\s+ENC_CHK", src)
    chk_g_defs   = re.findall(r"#define\s+CHK_G", src)
    assert len(enc_chk_defs) == 1, (
        f"Expected exactly 1 #define ENC_CHK (env_scratch block); "
        f"found {len(enc_chk_defs)}."
    )
    assert len(chk_g_defs) == 1, (
        f"Expected exactly 1 #define CHK_G (SignedData block); "
        f"found {len(chk_g_defs)}."
    )


def test_env_scratch_block_uses_chk_g_only():
    """The env_scratch backwards-write block must use ENC_CHK, not CHK_G or naked CHK()."""
    src = _read()
    # Locate the env_scratch block by its distinctive comment landmark and
    # the memmove that closes it.
    m = re.search(
        r"Inside this block use ENC_CHK.*?"
        r"memmove\s*\(\s*env_scratch\s*,",
        src, re.DOTALL)
    assert m, ("Could not locate env_scratch backwards-write block.  "
               "Did the cleanup landmark comment change from 'ENC_CHK' "
               "to something else?")
    body = m.group(0)
    # Search for CHK( that isn't ENC_CHK(.
    naked = re.findall(r"(?<!ENC_)\bCHK\(", body)
    assert not naked, (
        f"env_scratch block must use ENC_CHK() (not CHK_G or CHK) so "
        f"failures unwind via done:; found {len(naked)} plain CHK() or "
        f"CHK_G() invocation(s) that could leak enc_csr/enc_cek on error."
    )
    # Verify ENC_CHK is actually used (not just defined and never called).
    enc_chk_calls = re.findall(r"\bENC_CHK\(", body)
    assert len(enc_chk_calls) > 0, (
        "No ENC_CHK() calls found in env_scratch block -- macro is unused."
    )


def test_done_label_releases_renewal_secrets():
    """`done:` must free enc_csr, enc_cek (with zeroize), env_scratch and ra_crt."""
    src = _read()
    # Find the done: label block of scep_build_pkimessage_pkcsreq.  Stop at
    # the first `}` that follows a `return ret;`.
    m = re.search(r"\ndone:\n(.*?return\s+ret;\s*\n\})", src, re.DOTALL)
    assert m, "Could not locate `done:` cleanup label."
    body = m.group(1)
    for needed in [
        "mbedtls_x509_crt_free(&ra_crt)",
        "free(env_scratch)",
        "free(out_scratch)",
        "free(sa_content)",
        "free(enc_csr)",
        "free(enc_cek)",
    ]:
        assert needed in body, (
            f"`done:` cleanup is missing required call: {needed}.  "
            f"Without it, the env_scratch error path leaks heap/secret."
        )
    # The wrapped CEK should be zeroized before free.
    assert re.search(r"enc_cek_len.*?evp\[i\]\s*=\s*0", body, re.DOTALL), (
        "enc_cek should be zeroized before free at done:.  Search for "
        "a volatile-write loop using enc_cek_len."
    )
