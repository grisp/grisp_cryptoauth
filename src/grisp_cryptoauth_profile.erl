-module(grisp_cryptoauth_profile).

-include_lib("public_key/include/public_key.hrl").

-export([tls_client/6]).


tls_client(IssuerCert, {IssueDate, ExpireYears}, Serial, Subject, DERPubKey, GrispMeta) ->
    IssuerCertTBS = IssuerCert#'OTPCertificate'.tbsCertificate,
    #'OTPTBSCertificate'{
        version = v3,
        serialNumber = Serial,
        signature = grisp_cryptoauth_cert:sig_alg(),
        issuer = IssuerCertTBS#'OTPTBSCertificate'.subject,
        validity = grisp_cryptoauth_cert:validity(IssueDate, ExpireYears),
        subject = Subject,
        subjectPublicKeyInfo = grisp_cryptoauth_cert:subjPubKeyInfo(DERPubKey),
        extensions = grisp_cryptoauth_cert:build_ext([
            {ext_isCa, false},
            {ext_subjKeyId, DERPubKey},
            {ext_authKeyId, IssuerCert},
            {ext_keyUsage, [digitalSignature, keyAgreement]},
            {ext_extKeyUsage, client}
        ] ++ GrispMeta)
    }.
