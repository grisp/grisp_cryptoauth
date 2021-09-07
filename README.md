grisp_cryptoauth
================

Secure Element support for GRiSP2 based on cryptoauthlib.

Build
-----

This is meant to be build within the GRiSP2 toolchain.


Writing Certificates
--------------------

```
PrivateKey = public_key:generate_key({namedCurve, secp256r1}).
TBS = grisp_cryptoauth_template:test().
Cert = grisp_cryptoauth_cert:sign(TBS, PrivateKey).
grisp_cryptoauth:write_cert(device, Cert).
```


Reading Certificates
--------------------

```
TBS = grisp_cryptoauth_template:test().
grisp_cryptoauth:read_cert(device, TBS, plain).
```


Notes
-----

* We follow Microchips compressed certificate format [1] and OpenSSL 'best practice'
* The signature size is 64 bytes max, hence you should sign the device certificate over the P-256 curve
* The validity dates must align with an expire time of years, e.g. multiples of 365 days
* Like OpenSSL we use utcTime before (including) 2049 and generalTime afterwards

[1] https://ww1.microchip.com/downloads/en/Appnotes/20006367A.pdf
