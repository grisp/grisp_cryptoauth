-module(grisp_cryptoauth_cert_stritzinger).

-include_lib("public_key/include/public_key.hrl").

-export([device_template/0]).


device_template() ->
    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
	        version = v3,
            %%serialNumber = 16#40FFFFFFFFFFFFFFFFFF,
	        serialNumber = 302252471904080795963393,
            signature = #'SignatureAlgorithm'{
	            algorithm = ?'ecdsa-with-SHA256'
	        },
	        issuer = {rdnSequence, [[
     %%         pubkey_cert_records:transform(
                #'AttributeTypeAndValue'{
                    type = ?'id-at-commonName',
                    value = {utf8String, "www.grisp.org"}
                }
     %%         , encode)
            ]]},
            validity = #'Validity'{
                %%notBefore = {generalTime, "22222222222222Z"},
                %%notAfter =  {generalTime, "33333333333333Z"}
                notBefore = {generalTime, "20200101000000Z"},
                notAfter =  {generalTime, "20300101000000Z"}
            },
	        subject = {rdnSequence, [[
     %%         pubkey_cert_records:transform(
                #'AttributeTypeAndValue'{
                    type = ?'id-at-commonName',
                    value = {utf8String, "GRiSP2"}
                }
     %%         , encode)
            ]]},                                     
	        subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{
                algorithm = #'PublicKeyAlgorithm'{
                    algorithm = ?'id-ecPublicKey'
                },
                subjectPublicKey =
                    #'ECPoint'{point =
                        <<0:(8*64)>>
                    }
            }
	    },
        signatureAlgorithm = #'SignatureAlgorithm'{
	        algorithm = ?'ecdsa-with-SHA256'
        },
        signature = <<0:(8*71)>>
    }.
