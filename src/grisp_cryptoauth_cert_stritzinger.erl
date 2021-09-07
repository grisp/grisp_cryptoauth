-module(grisp_cryptoauth_cert_stritzinger).

-include_lib("public_key/include/public_key.hrl").

-export([template/0]).


template() ->
    IssuerCert = grisp_cryptoauth_cert:decode_pem_file("../priv/cert_test/intermediate_cert.pem"),
    IssuerCertTBS = IssuerCert#'OTPCertificate'.tbsCertificate,
    IssueDate = {{2021,9,1}, {0,0,0}},
    ExpireYears = 5,
    PubKeyBlob = <<0:(65*8)>>,
    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
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
	    },
        signatureAlgorithm =  grisp_cryptoauth_cert:sigAlg(),
        signature = <<48,68,2,32,122,103,30,182,212,65,23,148,112,160,79,229,117,7,201,253,
                      112,106,219,70,61,55,100,12,180,144,214,113,62,95,244,226,2,32,98,45,
                      118,26,149,170,104,3,84,35,89,78,106,107,240,160,71,161,105,26,56,121,
                      80,199,5,80,21,87,195,176,222,100>>
    }.
