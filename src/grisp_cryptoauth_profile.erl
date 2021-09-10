-module(grisp_cryptoauth_profile).

-include_lib("public_key/include/public_key.hrl").

-export([tls_client/5]).


tls_client(IssuerCert, {IssueDate, ExpireYears}, Serial, Subject, DERPubKey) ->
    IssuerCertTBS = IssuerCert#'OTPCertificate'.tbsCertificate,
    #'OTPTBSCertificate'{
        version = v3,
        serialNumber = Serial,
        signature = grisp_cryptoauth_cert:sig_alg(),
        issuer = IssuerCertTBS#'OTPTBSCertificate'.subject,
        validity = grisp_cryptoauth_cert:validity(IssueDate, ExpireYears),
        subject = Subject,
        subjectPublicKeyInfo = grisp_cryptoauth_cert:subjPubKeyInfo(DERPubKey),
        extensions = [
            grisp_cryptoauth_cert:ext_isCa(false),
            grisp_cryptoauth_cert:ext_subjkeyid(DERPubKey),
            grisp_cryptoauth_cert:ext_authkeyid(IssuerCert),
            grisp_cryptoauth_cert:ext_keyusage([digitalSignature, keyAgreement]),
            grisp_cryptoauth_cert:ext_extkeyusage(client)
        ]
    }.
