-module(grisp_cryptoauth_template).

-include_lib("public_key/include/public_key.hrl").

-export([test/0]).


issuer_cert() ->
<<"-----BEGIN CERTIFICATE-----
MIIB4DCCAUKgAwIBAgIBATAKBggqhkjOPQQDAjAPMQ0wCwYDVQQDDARyb290MB4X
DTIxMDkwNjE1MjI0NloXDTMxMDkwNDE1MjI0NlowFzEVMBMGA1UEAwwMaW50ZXJt
ZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIeo35aTGFRmCqt5OFW2w
gQcp+70HVWCOCjaBFmjAjX8dw/RyzWXms03geoNuxRWdLaJwOy47g/77AIOzz/+N
pKOBhjCBgzAMBgNVHRMEBTADAQH/MDgGA1UdIwQxMC+AFIBiOcLn0SzD6WGK3kb2
v1PELACpoROkETAPMQ0wCwYDVQQDDARyb290ggID6TAdBgNVHQ4EFgQUF9xB8fry
mlABcPuzG6wTy8YwAHkwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqG
SM49BAMCA4GLADCBhwJBfKts5a35296qf2KT+1Tl21Cxy+1+JQoAgAmFjtAbJMTx
RTi3ZRXB31J86iihcAkXSCCqti7pBM85iHmIQ+v1kYgCQgH2HjDkpJrdgh3WoWyy
EvHPxWQkWn4hQONSMu4lCY8R0tsJr0m4U+sVJs+GrxmiaEmrcjWO55x9IwGZBxuM
GVh3ZQ==
-----END CERTIFICATE-----">>.


test() ->
    IssuerCert = grisp_cryptoauth_cert:decode_pem(issuer_cert()),
    IssuerCertTBS = IssuerCert#'OTPCertificate'.tbsCertificate,
    IssueDate = {{2021,9,1}, {0,0,0}},
    ExpireYears = 5,
    PubKeyBlob = <<4,109,220,77,238,124,58,236,54,132,168,190,179,110,123,161,
                   140,75,181,236,209,197,123,110,169,233,214,7,127,204,182,
                   215,77,227,214,133,58,247,44,163,184,81,162,36,49,11,17,252,
                   217,155,174,8,195,223,167,142,153,71,156,107,48,216,101,15,
                   161>>,
    #'OTPTBSCertificate'{
        version = v3,
        serialNumber = 1,
        signature = grisp_cryptoauth_cert:sig_alg(),
        issuer = IssuerCertTBS#'OTPTBSCertificate'.subject,
        validity = grisp_cryptoauth_cert:validity(IssueDate, ExpireYears),
        subject = {rdnSequence, [[
            #'AttributeTypeAndValue'{
                type = ?'id-at-commonName',
                value = {utf8String, "client"}
            }
        ]]},
        subjectPublicKeyInfo = grisp_cryptoauth_cert:subjPubKeyInfo(PubKeyBlob),
        extensions = [
            grisp_cryptoauth_cert:ext_is_ca(false),
            grisp_cryptoauth_cert:ext_subjkeyid(PubKeyBlob),
            grisp_cryptoauth_cert:ext_authkeyid(IssuerCert),
            grisp_cryptoauth_cert:ext_keyusage([digitalSignature, keyAgreement]),
            grisp_cryptoauth_cert:ext_extkeyusage(client)
        ]
    }.
