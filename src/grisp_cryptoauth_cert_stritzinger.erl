-module(grisp_cryptoauth_cert_stritzinger).

-include_lib("public_key/include/public_key.hrl").

-export([template/0]).


template() ->
    IssuerCert = grisp_cryptoauth_cert:decode_pem_file("../priv/cert_test/intermediate_cert.pem"),
    IssuerCertTBS = IssuerCert#'OTPCertificate'.tbsCertificate,
    IssueDate = {{2021,9,1}, {0,0,0}},
    ExpireYears = 5,
    PubKeyBlob = <<0:(65*8)>>,
    #'OTPTBSCertificate'{
        version = v3,
        serialNumber = 1,
        signature = grisp_cryptoauth_cert:sigAlg(),
        issuer = IssuerCertTBS#'OTPTBSCertificate'.subject,
        validity = grisp_cryptoauth_cert:validity(IssueDate, ExpireYears),
        subject = {rdnSequence, [[
            #'AttributeTypeAndValue'{
                type = ?'id-at-commonName',
                value = {utf8String, "GRiSP2"}
            }
        ]]},
        subjectPublicKeyInfo = grisp_cryptoauth_cert:subjPubKeyInfo(PubKeyBlob),
        extensions = [
            grisp_cryptoauth_cert:ext_is_ca(false),
            grisp_cryptoauth_cert:ext_subjkeyid(PubKeyBlob),
            grisp_cryptoauth_cert:ext_authkeyid(IssuerCert)
        ]
    }.
