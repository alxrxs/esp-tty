"""
native_link_openssl.py -- PlatformIO extra_script that adds -lcrypto to the
native test environment so wolfCrypt stubs can call OpenSSL SHA-256 and base64.
"""
Import("env")  # noqa: F821  (PlatformIO injects this)

env.Append(LIBS=["crypto"])
