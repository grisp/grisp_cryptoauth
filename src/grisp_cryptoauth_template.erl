-module(grisp_cryptoauth_template).

-include_lib("public_key/include/public_key.hrl").

-export([grisp2/0, test/0]).


%% Default GRiSP2 certificate.
grisp2() ->
    IssuerCert = grisp_cryptoauth_cert:decode_pem(
                   grisp_cryptoauth_known_certs:test_intermediate()),
    IssueDateInfo = {{{2021,9,1}, {0,0,0}}, no_expiration},
    {ok, DERPubKey} = grisp_cryptoauth:public_key(primary),
    {ok, GrispMeta} = grisp_hw:eeprom_read(),
    Serial = maps:get(grisp_serial, GrispMeta),
    Subject = {rdnSequence, [[
        #'AttributeTypeAndValue'{
            type = ?'id-at-commonName',
            value = {utf8String, "GRiSP2 " ++ integer_to_list(Serial)}
        }
    ]]},
    grisp_cryptoauth_profile:tls_client(IssuerCert, IssueDateInfo,
                                        Subject, DERPubKey, GrispMeta).


%% Just used for testing, no access to
%% issuer certificate, Secure Element
%% or EEPROM needed.
test() ->
    IssuerCert = grisp_cryptoauth_cert:decode_pem(
                   grisp_cryptoauth_known_certs:test_intermediate()),
    IssueDateInfo = {{{2021,9,1}, {0,0,0}}, no_expiration},
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
    GrispMeta = #{
        grisp_version       => "2",
        grisp_serial        => 1,
        grisp_pcb_version   => "1.2",
        grisp_pcb_variant   => 1,
        grisp_batch         => 1,
        grisp_prod_date     => {{2021,9,1}, {0,0,0}}},
    grisp_cryptoauth_profile:tls_client(IssuerCert, IssueDateInfo,
                                        Subject, DERPubKey, GrispMeta).
