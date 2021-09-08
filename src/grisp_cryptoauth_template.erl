-module(grisp_cryptoauth_template).

-include_lib("public_key/include/public_key.hrl").

-export([test/0]).


test() ->
    IssuerCert = grisp_cryptoauth_cert:decode_pem_file("../priv/cert_test/intermediate_cert.pem"),
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
        signature = grisp_cryptoauth_cert:sigAlg(),
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
