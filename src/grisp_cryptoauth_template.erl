-module(grisp_cryptoauth_template).

-export([grisp2_device/1,
         grisp2_intermediate/1,
         stritzinger_root/1,
         test/1]).


-define(SERIAL_STRITZINGER_ROOT_CA, 1).
-define(SERIAL_INTERMEDIATE_CA, 2).


%% GRiSP2 device certificate.
grisp2_device(Context) ->
    IssuerCertFile = code:priv_dir(grisp_cryptoauth) ++ "/grisp2_ca.pem",
    {ok, IssuerCertPEM} = file:read_file(IssuerCertFile),
    IssuerCert = grisp_cryptoauth_cert:decode_pem(IssuerCertPEM),
    Validity = {{{2021,9,1}, {0,0,0}}, no_expiration},
    {ok, DERPubKey} = grisp_cryptoauth:public_key(Context, primary),
    {ok, GrispMeta} = grisp_hw:eeprom_read(),
    %% The device serial is also used for the certificate serial, simply
    %% because it is unique integer. If we want to use other serials in
    %% the future then that's ok, there's no requirement on such a
    %% mapping between both serials.
    Serial = maps:get(grisp_serial, GrispMeta),
    Subject = #{
        'CN' => "GRiSP2 device " ++ integer_to_list(Serial),
        'O'  => "Dipl.Phys. Peer Stritzinger GmbH",
        'OU' => "www.grisp.org",
        emailAddress => "grisp@stritzinger.com"
    },
    grisp_cryptoauth_profile:tls_client(IssuerCert, Validity, Subject, DERPubKey, GrispMeta).


%% GRiSP2 intermediate CA certificate.
grisp2_intermediate(Context) ->
    IssuerCertFile = code:priv_dir(grisp_cryptoauth) ++ "/stritzinger_root.pem",
    {ok, IssuerCertPEM} = file:read_file(IssuerCertFile),
    IssuerCert = grisp_cryptoauth_cert:decode_pem(IssuerCertPEM),
    Validity = {{{2021,9,1}, {0,0,0}}, no_expiration},
    {ok, DERPubKey} = grisp_cryptoauth:public_key(Context, primary),
    Serial = ?SERIAL_INTERMEDIATE_CA,
    Subject = #{
        'CN' => "GRiSP2 CA",
        'O'  => "Dipl.Phys. Peer Stritzinger GmbH",
        'OU' => "www.grisp.org",
        emailAddress => "grisp@stritzinger.com"
    },
    grisp_cryptoauth_profile:intermediate_ca(IssuerCert, Serial, Validity, Subject, DERPubKey).


%% Stritzinger root CA certificate.
stritzinger_root(Context) ->
    Validity = {{{2021,9,1}, {0,0,0}}, no_expiration},
    {ok, DERPubKey} = grisp_cryptoauth:public_key(Context, primary),
    Serial = ?SERIAL_STRITZINGER_ROOT_CA,
    Subject = #{
        'CN' => "Stritzinger Root CA",
        'O'  => "Dipl.Phys. Peer Stritzinger GmbH",
        'OU' => "www.stritzinger.com",
        'C'  => "DE",
        'L'  => "Munich",
        emailAddress => "info@stritzinger.com"
    },
    grisp_cryptoauth_profile:root_ca(Serial, Validity, Subject, DERPubKey).


%% Just used for testing, no access to issuer certificate, Secure Element
%% or EEPROM needed. Compile .erl files locally and execute this function.
test(_Context) ->
    IssuerCertFile = code:priv_dir(grisp_cryptoauth) ++ "/cert_test/intermediate_cert.pem",
    {ok, IssuerCertPEM} = file:read_file(IssuerCertFile),
    IssuerCert = grisp_cryptoauth_cert:decode_pem(IssuerCertPEM),
    Validity = {{{2021,9,1}, {0,0,0}}, no_expiration},
    Subject = #{'CN' => "client"},
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
    grisp_cryptoauth_profile:tls_client(IssuerCert, Validity, Subject, DERPubKey, GrispMeta).
