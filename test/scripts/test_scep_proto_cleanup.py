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

This test guards against regressing back to plain CHK() inside that
block by:
  - asserting that CHK_G is defined at least twice in the file (once
    for the env_scratch block, once for the outer SignedData block);
  - asserting that the env_scratch block (delimited by two well-known
    landmarks) contains no naked CHK() invocations;
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
    """CHK_G must be re-defined for both the env_scratch and SignedData blocks."""
    src = _read()
    defs = re.findall(r"#define\s+CHK_G", src)
    assert len(defs) >= 2, (
        f"Expected at least 2 #define CHK_G (env_scratch + SignedData "
        f"blocks); found {len(defs)}."
    )


def test_env_scratch_block_uses_chk_g_only():
    """The env_scratch backwards-write block must not contain naked CHK()."""
    src = _read()
    # Locate the env_scratch block by its distinctive comment landmark and
    # the memmove that closes it.
    m = re.search(
        r"Inside this block use CHK_G.*?"
        r"memmove\s*\(\s*env_scratch\s*,",
        src, re.DOTALL)
    assert m, ("Could not locate env_scratch backwards-write block.  "
               "Did the cleanup landmark comment change?")
    body = m.group(0)
    # Search for CHK( that isn't CHK_G(.
    naked = re.findall(r"(?<!_)\bCHK\(", body)
    assert not naked, (
        f"env_scratch block must use CHK_G() so failures unwind via "
        f"done:; found {len(naked)} naked CHK() invocation(s) that would "
        f"leak enc_csr/enc_cek on error."
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
