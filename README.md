grisp_cryptoauth
================

An OTP library

Build
-----

    $ rebar3 compile

Notes
-----

* We follow Microchips compressed certificate format [1] and OpenSSL 'best practice'
* The signature size is 64 bytes max, hence you should sign the device certificate over the P-256 curve
* The validity dates must align with an expire time of years, e.g. multiples of 365 days
* Like OpenSSL we use utcTime before 2049 and generalTime afterwards

[1] https://ww1.microchip.com/downloads/en/Appnotes/20006367A.pdf
