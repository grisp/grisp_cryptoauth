grisp_cryptoauth
================

Secure Element (Microchip ATECC608B) support for GRiSP2 based on cryptoauthlib.

Using `grisp_cryptoauth` it is possible to set up TLS connections using private
keys and certificates stored within the ATECC608B. Both PKCS11 (using Erlang's
crypto engines) and 'plain' access to the device can be used. The latter currently
requires an additional patch. RTEMS based GRiSP2 applications can't use PKCS11
due to restrictions on dynamic libraries.


Build
-----

This is meant to be build within the GRiSP2 toolchain or on a linux distribution
with cryptoauthlib installed, build within the `grisp_linux_builder`.

Just add it as dependency in rebar3 in your main application.


Device Support
--------------

This library follows the ATECC608B-TFLXTLS configuration, that means in particular:

* one unchangable primary private key
* three changable secondary private keys
* sign and verify operations on the keys above
* two (primary and secondary) changable slots for compressed certificates
* possibility to lock slots if you really want to
* high quality random byte generator

More to come :).


Setting up TLS
--------------
Erlang's `ssl` library is used for setting up TLS/mTLS. For the device
you need to honor at least the following options:
#### OTP >= 27
```
{certs_keys, [#{
    cert => ClientChain,
    key => #{
        algorithm => ecdsa,
        sign_fun => fun grisp_cryptoauth:sign_fun/3
    }
}]}
```
#### Legacy tls options: OTP =< 26
There is a patch necessary to make use of `grisp_cryptoauth` for TLS. This
patch is included in this repository and is tested for Erlang `23.3.4.10`, this patch has been adapted and maintained until OTP 26. We do not apply any SSL patch as form OTP 27.

```
%% device certificate
{cert, grisp_cryptoauth:read_cert(primary, der)}

%% access to primary private key for TLS handshake
{key, #{algorithm => ecdsa, sign_fun => {grisp_cryptoauth, sign_fun}}}
```

Don't forget to also add the appropriate CA certificates using e.g. the
`cacerts` option! You can read the CA certificate files using e.g.

```
grisp_cryptoauth_cert:decode_pem_file("path/to/file", der)
```

There have been problems in erlang 23 with mTLS. If (and only if) problems
occur try adding one or both of the following options to enforce proper behaviour:

```
{signature_algs, [{sha256, ecdsa}]}
{signature_algs_cert, [ecdsa_secp256r1_sha256]}
```


Writing Certificates
--------------------

```
PrivateKey = public_key:generate_key({namedCurve, secp256r1}).
Cert = grisp_cryptoauth_cert:sign(test, PrivateKey).
grisp_cryptoauth:write_cert(primary, test, Cert).
```


Outlook
-------

This library currently contains functionalities that should be split into
a couple of new libraries, in particular:

* NIF based library for `cryptoauthlib` supporting more devices
* certificate handling library, nice glue for Erlang certificate records
* client package for supporting GRiSP2 SaaS system


Notes
-----

* We follow Microchips compressed certificate format [1] and OpenSSL 'best practice'
* The signature size is 64 bytes max, hence you should sign the device certificate over the P-256 curve
* The above point means that you need to use a P-256 based CA key
* The validity dates must align with an expire time of years, e.g. multiples of 365 days
* Like OpenSSL we use utcTime before (including) 2049 and generalTime afterwards for certificate validity

[1] https://ww1.microchip.com/downloads/en/Appnotes/20006367A.pdf
