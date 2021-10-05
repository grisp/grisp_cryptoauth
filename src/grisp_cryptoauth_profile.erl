-module(grisp_cryptoauth_profile).

-include_lib("public_key/include/public_key.hrl").

-export([tls_client/5]).


tls_client(IssuerCert, {IssueDate, ExpireYears}, Subject, DERPubKey, GrispMeta) ->
    IssuerCertTBS = IssuerCert#'OTPCertificate'.tbsCertificate,
    Serial = maps:get(grisp_serial, GrispMeta),
    #'OTPTBSCertificate'{
        version = v3,
        serialNumber = Serial,
        signature = grisp_cryptoauth_cert:sigAlg(),
        issuer = IssuerCertTBS#'OTPTBSCertificate'.subject,
        validity = grisp_cryptoauth_cert:validity(IssueDate, ExpireYears),
        subject = Subject,
        subjectPublicKeyInfo = grisp_cryptoauth_cert:subPubKeyInfo(DERPubKey),
        extensions = grisp_cryptoauth_cert:build_standard_ext([
            {ext_isCa, false},
            {ext_subKeyId, DERPubKey},
            {ext_authKeyId, IssuerCert},
            {ext_keyUsage, [digitalSignature, keyAgreement]},
            {ext_extKeyUsage, client}
        ]) ++ [grisp_cryptoauth_cert:build_grisp_ext(GrispMeta)]
    }.
