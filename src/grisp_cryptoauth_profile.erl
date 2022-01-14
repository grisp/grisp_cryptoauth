-module(grisp_cryptoauth_profile).

-include_lib("public_key/include/public_key.hrl").

-export([tls_client/5,
         intermediate_ca/5,
         root_ca/4]).


tls_client(IssuerCert, {IssueDate, ExpireYears}, Subject, DERPubKey, GrispMeta) ->
    IssuerCertTBS = IssuerCert#'OTPCertificate'.tbsCertificate,
    Serial = maps:get(grisp_serial, GrispMeta),
    #'OTPTBSCertificate'{
        version = v3,
        serialNumber = Serial,
        signature = grisp_cryptoauth_cert:sigAlg(),
        issuer = IssuerCertTBS#'OTPTBSCertificate'.subject,
        validity = grisp_cryptoauth_cert:validity(IssueDate, ExpireYears),
        subject = grisp_cryptoauth_cert:distinguished_name(Subject),
        subjectPublicKeyInfo = grisp_cryptoauth_cert:subPubKeyInfo(DERPubKey),
        extensions = grisp_cryptoauth_cert:build_standard_ext([
            {ext_subKeyId, DERPubKey},
            {ext_authKeyId, IssuerCert},
            {ext_keyUsage, [digitalSignature, keyAgreement]},
            {ext_extKeyUsage, client}
        ]) ++ [grisp_cryptoauth_cert:build_grisp_ext(GrispMeta)]
    }.


intermediate_ca(IssuerCert, Serial, {IssueDate, ExpireYears}, Subject, DERPubKey) ->
    IssuerCertTBS = IssuerCert#'OTPCertificate'.tbsCertificate,
    #'OTPTBSCertificate'{
        version = v3,
        serialNumber = Serial,
        signature = grisp_cryptoauth_cert:sigAlg(),
        issuer = IssuerCertTBS#'OTPTBSCertificate'.subject,
        validity = grisp_cryptoauth_cert:validity(IssueDate, ExpireYears),
        subject = grisp_cryptoauth_cert:distinguished_name(Subject),
        subjectPublicKeyInfo = grisp_cryptoauth_cert:subPubKeyInfo(DERPubKey),
        extensions = grisp_cryptoauth_cert:build_standard_ext([
            {ext_isCa, true},
            {ext_subKeyId, DERPubKey},
            {ext_authKeyId, IssuerCert},
            {ext_keyUsage, [keyCertSign, cRLSign]}
        ])
    }.


root_ca(Serial, {IssueDate, ExpireYears}, Subject, DERPubKey) ->
    #'OTPTBSCertificate'{
        version = v3,
        serialNumber = Serial,
        signature = grisp_cryptoauth_cert:sigAlg(),
        issuer = grisp_cryptoauth_cert:distinguished_name(Subject),
        validity = grisp_cryptoauth_cert:validity(IssueDate, ExpireYears),
        subject = grisp_cryptoauth_cert:distinguished_name(Subject),
        subjectPublicKeyInfo = grisp_cryptoauth_cert:subPubKeyInfo(DERPubKey),
        extensions = grisp_cryptoauth_cert:build_standard_ext([
            {ext_isCa, true},
            {ext_subKeyId, DERPubKey},
            {ext_keyUsage, [keyCertSign, cRLSign]}
        ])
    }.
