# MQTT TLS test fixtures

These certificates are TEST-ONLY fixtures. They are signed by local test CAs and must never be used in production.

## Files

- ca.pem — trusted test root CA; use as the CA file for normal tests.
- client.crt / client.key — client certificate and private key signed by ca.pem.
- server.crt / server.key — server certificate and private key signed by ca.pem; valid for localhost and 127.0.0.1.
- wrong_ca.pem — unrelated CA for negative verification tests.
- wrong_client.crt / wrong_client.key — client certificate signed by wrong_ca.pem.

The private keys are intentionally unencrypted because they are test fixtures.
