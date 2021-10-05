grisp_cryptoauth
================

Secure Element (Microchip ATECC608B) support for GRiSP2 based on cryptoauthlib.

Build
-----

This is meant to be build within the GRiSP2 toolchain or on a linux distribution
with cryptoauthlib installed.

For Linux:

```
rebar3 compile
```

For local testing on GRiSP2 when used as standalone release:

```
GRISP=1 rebar3 grisp build
```


Support
-------

This library follows the ATECC608B-TFLXTLS configuration, that means in particular:

* one unchangable primary private key
* three changable secondary private keys
* sign and verify operations on the keys above
* two (primary and secondary) changable slots for compressed certificates
* possibility to lock slots if you really want to

More to come :).


Writing Certificates
--------------------

```
PrivateKey = public_key:generate_key({namedCurve, secp256r1}).
Cert = grisp_cryptoauth_cert:sign(test, PrivateKey).
grisp_cryptoauth:write_cert(primary, test, Cert).
```


Reading Certificates
--------------------

```
grisp_cryptoauth:read_cert(primary, plain).
grisp_cryptoauth:read_cert(primary, der).
```


Notes
-----

* We follow Microchips compressed certificate format [1] and OpenSSL 'best practice'
* The signature size is 64 bytes max, hence you should sign the device certificate over the P-256 curve
* The above point means that you need to use a P-256 based CA key
* The validity dates must align with an expire time of years, e.g. multiples of 365 days
* Like OpenSSL we use utcTime before (including) 2049 and generalTime afterwards for certificate validity

[1] https://ww1.microchip.com/downloads/en/Appnotes/20006367A.pdf
