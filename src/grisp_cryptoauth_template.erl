-module(grisp_cryptoauth_template).

-include_lib("public_key/include/public_key.hrl").

-export([test/0]).


test() ->
    IssuerCert = grisp_cryptoauth_cert:decode_pem(
                   grisp_cryptoauth_known_certs:test_intermediate()),
    IssueDateInfo = {{{2021,9,1}, {0,0,0}}, 5},
    Serial = 1,
    Subject = {rdnSequence, [[
        #'AttributeTypeAndValue'{
            type = ?'id-at-commonName',
            value = {utf8String, "client"}
        }
    ]]},
    DERPubKey = <<4,109,220,77,238,124,58,236,54,132,168,190,179,110,123,161,
                  140,75,181,236,209,197,123,110,169,233,214,7,127,204,182,
                  215,77,227,214,133,58,247,44,163,184,81,162,36,49,11,17,252,
                  217,155,174,8,195,223,167,142,153,71,156,107,48,216,101,15,
                  161>>,
    grisp_cryptoauth_profile:tls_client(IssuerCert, IssueDateInfo, Serial,
                                        Subject, DERPubKey).
