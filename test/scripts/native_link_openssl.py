"""
native_link_openssl.py -- PlatformIO extra_script that adds OpenSSL and
mbedTLS libraries to the native test environment.

- OpenSSL (-lcrypto, -lssl): used by wolfSSL stubs for CSR/cert verification
  in test/stubs/wolfssl/wolfcrypt/
- mbedTLS (-lmbedcrypto, -lmbedx509, -lmbedtls): used directly by
  scep_proto.c (all RSA/AES/PKCS#7 operations now use mbedTLS).
"""
Import("env")  # noqa: F821  (PlatformIO injects this)

env.Append(LIBS=["crypto", "mbedcrypto", "mbedx509", "mbedtls", "pthread"])
