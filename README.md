Simple CRL validation test for Erlang.
--------------------------------------

Currently Erlang has undocumented support for checking Certificate Revocation
Lists (CRLs) when validating peer certificates. Due to the almost total lack of
documentation, however, this can be challenging to implement.

Here is a sample SSL client/server with a client that supports checking the CRL
of the server's certificate. It uses a modified make_cert.erl from OTP's SSL
tests to generate 2 CAs and a bunch of certificates (and CRLs) and revokes one
of them.

The client then connects 3 times, to 3 different ports, 5555, 5556 and 5557.
Those ports are, respectively, a certificate signed by the root CA, a
certificate signed by an intermediate CA and a *revoked* certificate signed by
an intermediate CA. Thus the expected behaviour is for the first two connections
to succeed and the third to fail.

To run the tests, simply run 'make check'.

Currently the latest release of Erlang, R16B02, has a bug in pubkey_crl.erl
which makes this test fail if you don't use a patched beam. You only have to
change one line, line 42:

```erlang
AltNames = subject_alt_names(TBSCert#'OTPTBSCertificate'.extensions),
```
Needs to be changed to:

```erlang
AltNames = (pubkey_cert:select_extension(?'id-ce-subjectAltName', TBSCert#'OTPTBSCertificate'.extensions))#'Extension'.extnValue
```

Just drop the patched .beam into the ebin directory, and the test should start
passing.
