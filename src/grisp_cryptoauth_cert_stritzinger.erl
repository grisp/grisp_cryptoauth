-module(grisp_cryptoauth_cert_stritzinger).

-include_lib("public_key/include/public_key.hrl").

-export([device_template/0]).


device_template() ->
    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
	        version = v3,
	        serialNumber = 16#FFFFFFFF,
            signature = #'SignatureAlgorithm'{
	            algorithm = ?'ecdsa-with-SHA256',
	            parameters = asn1_NOVALUE
	        },
	        issuer = {rdnSequence, [[
                #'AttributeTypeAndValue'{
                    type = ?'id-at-commonName',
                    value = <<"grisp.org">>
                }
            ]]},
            validity = #'Validity'{
                notBefore = {generalTime, "20200101000000Z"},
                notAfter = {generalTime, "20300101000000Z"}
            },
	        subject = {rdnSequence, [[
                #'AttributeTypeAndValue'{
                    type = ?'id-at-commonName',
                    value = <<"GRiSP2">>
                }
            ]]},                                     
	        subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{
                algorithm = #'PublicKeyAlgorithm'{
                    algorithm = ?'id-ecPublicKey',
                    parameters = asn1_NOVALUE
                },
                subjectPublicKey = <<0:(8*65)>>
            }
	    },
        signatureAlgorithm = #'SignatureAlgorithm'{
	        algorithm = ?'ecdsa-with-SHA256',
	        parameters = asn1_NOVALUE
        },
        signature = <<0:(8*64)>>
    }.
