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


Development
-----------

When included as a dependency in an application, is is possible to define
the macro ENUMATE_CRYPTOAUTH using overrides:

        {overrides, [
            {add, grisp_cryptoauth, [{erl_opts, [{d, 'EMULATE_CRYPTOAUTH'}]}]}
        ]},

With this defined, the extra configuration keys `client_cert`, `client_key` and
`tls_verify` can be specified to be used instead of the secure element.

This allow an application depending on grisp_cryptoauth to run tests and local
shell.


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


Configuring TLS Options
-----------------------

By configuring grisp_cryptoauth, multiple application can request the TLS
options required to connect to a given server, assuming that all the servers
have the same security requirments. The following options are used to build
the TLS options:


* `tls_use_client_certificate`

Configures if TLS cponnections should use the client certificate. Default: true.


* `tls_client_trusted_certs`

Configures the client trusted certificates.

Should provide all the additional certificates required to validate to the
client root CA, alongside the `tls_client_trusted_certs_cb` option.

Point to a directory from where all the `.pem` and `.crt` files will be loaded,
or to a single PEM file that could contain multiple certificates.

The configuration could either be an absolute path, a path relative to the
`priv` directory of a given application, or a path relative to an application
`test` directory.

If not specified, it will use the default certificate chain matching the
client certificate.

e.g.

```Erlang
{tls_client_trusted_certs, "/absolute/path/to/directory"}
{tls_client_trusted_certs, "/absolute/path/to/single.pem"}
{tls_client_trusted_certs, {priv, my_app, "relative/path/to/directory"}}
{tls_client_trusted_certs, {priv, my_app, "relative/path/to/single.pem"}}
{tls_client_trusted_certs, {test, my_app, "relative/path/to/directory"}}
{tls_client_trusted_certs, {test, my_app, "relative/path/to/single.pem"}}
```

* `tls_client_trusted_certs_cb`

Configures the client trusted certificates.

Should provide all the additional certificates required to validate to the
client root CA, alongside the `tls_client_trusted_certs` option.

Define a callback function the will return the client trusted certificates
as a list of DER encoded certificates.

e.g.

```Erlang
{tls_client_trusted_certs_cb, {my_mod, my_fun}}}
{tls_client_trusted_certs_cb, {my_mod, my_fun, [some, arguments]}}}
```

* `tls_server_trusted_certs`

Configures the server trusted certificates.

Should provide the certification chain for veryfying the server certificates,
alongside the `tls_server_trusted_certs_cb` option.

Point to a directory that should contain a PEM file with extension `.pem`
or `.crt` with the name of the domain the TLS connection is for. If multiple
certificates are required, the file must contain the full chain.
If the path is set to `/foo/bar`, and the server doain name is `grisp.org`,
the TLS configuration will try the certificate `/foo/bar/grisp.org.pem` or
`/foo/bar/grisp.org.crt` if any exists.

The configuration could either be an absolute path, a path relative to the
`priv` directory of a given application, or a path relative to an application
`test` directory.

e.g.

```Erlang
{tls_server_trusted_certs, "/absolute/path/to/directory"}
{tls_server_trusted_certs, {priv, my_app, "relative/path/to/directory"}}
{tls_server_trusted_certs, {test, my_app, "relative/path/to/directory"}}
```

* `tls_server_trusted_certs_cb`

Configures the server trusted certificates.

Should provide the certification chain for veryfying the server certificates,
alongside the `tls_server_trusted_certs` option.

Define a callback function the will return the client trusted certificates
as a list of DER encoded certificates.

e.g.

```Erlang
{tls_server_trusted_certs_cb, {certifi, cacerts}}}
{tls_server_trusted_certs_cb, {my_mod, my_fun, [some, arguments]}}}
```

* `client_certs`

When EMULATE_CRYPTOAUTH macro is defined, this configures the certificate to
use instead of the secure element's one when generating TLS options.

The configuration could either be an absolute path, a path relative to the
`priv` directory of a given application, or a path relative to an application
`test` directory.

e.g.

```Erlang
{client_certs, "/absolute/path/to/some.pem"}
{client_certs, {priv, my_app, "relative/path/to/some.crt"}}
{client_certs, {test, my_app, "relative/cert.pem"}}
```

* `client_key`

When EMULATE_CRYPTOAUTH macro is defined, this configures the private key to
use instead of the secure element's one when generating TLS options.

The configuration could either be an absolute path, a path relative to the
`priv` directory of a given application, or a path relative to an application
`test` directory.

e.g.

```Erlang
{client_key, "/absolute/path/to/some.pem"}
{client_key, {priv, my_app, "relative/path/to/some.key"}}
{client_key, {test, my_app, "relative/key.pem"}}
```

* `tls_verify`

When EMULATE_CRYPTOAUTH macro is defined, this allow overriding server
certificate verification for development or testing. By default it is
`verify_peer` but can be set to `verify_none`.

e.g.

```Erlang
{tls_verify, verify_none}
```


Setting Up TLS Manually
-----------------------

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
patch is included in this repository and is tested for Erlang `23.3.4.10`, this patch has been adapted and maintained until OTP 26. We do not apply any SSL patch from OTP 27.

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
