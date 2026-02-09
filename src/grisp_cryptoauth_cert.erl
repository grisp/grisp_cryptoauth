-module(grisp_cryptoauth_cert).

-include_lib("public_key/include/public_key.hrl").

%% Public API
-export([decode_pem_file/2,
         decode_pem/2,
         encode_pem/1,
         sign/2,
         compress/3,
         decompress/2,
         print/1,
         distinguished_name/1,
         add_years/2,
         subPubKeyInfo/1,
         sigAlg/0,
         validity/2,
         build_standard_ext/1,
         build_grisp_ext/1]).

%% Testing
-export([compress_sig/1,
         decompress_sig/1,
         compress_date/1,
         decompress_date/1,
         ext_authKeyId/1,
         ext_subKeyId/1,
         ext_keyUsage/1,
         ext_extKeyUsage/1,
         ext_isCa/1,
         calc_expire_years/1,
         encode_grisp_meta/1,
         decode_grisp_meta/1]).

-define(MAX_NOT_AFTER, {generalTime, "99991231235959Z"}).
-define('id-stritzinger-grispMeta',         {1,3,6,1,4,1,4849,0}).
-define('id-stritzinger-grispVersion',      {1,3,6,1,4,1,4849,1}).
-define('id-stritzinger-grispSerial',       {1,3,6,1,4,1,4849,2}).
-define('id-stritzinger-grispPcbVersion',   {1,3,6,1,4,1,4849,3}).
-define('id-stritzinger-grispPcbVariant',   {1,3,6,1,4,1,4849,4}).
-define('id-stritzinger-grispBatch',        {1,3,6,1,4,1,4849,5}).
-define('id-stritzinger-grispProdDate',     {1,3,6,1,4,1,4849,6}).


decode_pem_file(FilePath, Type) ->
    decode_pem(element(2, file:read_file(FilePath)), Type).


decode_pem(PEM, der) ->
    element(2, hd(public_key:pem_decode(PEM)));
decode_pem(PEM, plain) ->
    public_key:pkix_decode_cert(
      element(2, hd(public_key:pem_decode(PEM))), otp).


encode_pem(#'OTPCertificate'{} = Cert) ->
    public_key:pem_encode(
        [{'Certificate',
          public_key:pkix_encode('OTPCertificate', Cert, otp),
          not_encrypted}]).


sign(#'OTPTBSCertificate'{} = TBS, SignFun) when is_function(SignFun) ->
    DER = public_key:pkix_encode('OTPTBSCertificate', TBS, otp),
    Sig = SignFun(DER), %% expect bare signature here
    build_cert_from_tbs(TBS, Sig);
sign(#'OTPTBSCertificate'{} = TBS, {node, Node}) ->
    DER = public_key:pkix_encode('OTPTBSCertificate', TBS, otp),
    {ok, Sig} = rpc:call(Node, grisp_cryptoauth, sign, [primary, DER]),
    build_cert_from_tbs(TBS, Sig);
sign(#'OTPTBSCertificate'{} = TBS, PrivateKey) ->
    public_key:pkix_decode_cert(
      public_key:pkix_sign(TBS, PrivateKey), otp);
sign({Mod, Fun}, SignFunOrPrivateKey) ->
    sign(Mod:Fun(undefined), SignFunOrPrivateKey);
sign(Fun, SignFunOrPrivateKey) when is_atom(Fun) ->
    sign(grisp_cryptoauth_template:Fun(undefined), SignFunOrPrivateKey).

sigAlg() ->
    #'SignatureAlgorithm'{algorithm = ?'ecdsa-with-SHA256'}.


validity(TS, no_expiration) ->
    #'Validity'{
        notBefore = ts_to_utc_or_general_time(TS),
        notAfter =  ?MAX_NOT_AFTER
    };
validity(TS, Years) ->
    #'Validity'{
        notBefore = ts_to_utc_or_general_time(TS),
        notAfter =  add_years(TS, Years)
    }.


subPubKeyInfo(PubKeyBlob) ->
    #'OTPSubjectPublicKeyInfo'{
       algorithm =
         #'PublicKeyAlgorithm'{
           algorithm = ?'id-ecPublicKey',
           parameters = {namedCurve, ?'secp256r1'}},
       subjectPublicKey =
         #'ECPoint'{point = PubKeyBlob}
    }.


build_standard_ext(ExtList) ->
    Fun = fun({ExtFunName, Val}) -> ?MODULE:ExtFunName(Val) end,
    lists:map(Fun, ExtList).


build_grisp_ext(GrispMeta) ->
    #'Extension'{
       extnID = ?'id-stritzinger-grispMeta',
       extnValue = encode_grisp_meta(GrispMeta)}.


encode_grisp_meta(GrispMeta) ->
    %% Encode all GRiSP meta data as a 'map', e.g. a
    %% Sequence of Sequences of length 2 (for key and value)
    %% Note: we enforce order here!
    asn1rt_nif:encode_ber_tlv({16,
        [{16, [der_encode_ObjectIdentifier(?'id-stritzinger-grispVersion'),
               der_encode_IA5String(maps:get(grisp_version, GrispMeta))]},
         {16, [der_encode_ObjectIdentifier(?'id-stritzinger-grispSerial'),
               der_encode_Integer(maps:get(grisp_serial, GrispMeta))]},
         {16, [der_encode_ObjectIdentifier(?'id-stritzinger-grispPcbVersion'),
               der_encode_IA5String(maps:get(grisp_pcb_version, GrispMeta))]},
         {16, [der_encode_ObjectIdentifier(?'id-stritzinger-grispPcbVariant'),
               der_encode_Integer(maps:get(grisp_pcb_variant, GrispMeta))]},
         {16, [der_encode_ObjectIdentifier(?'id-stritzinger-grispBatch'),
               der_encode_Integer(maps:get(grisp_batch, GrispMeta))]},
         {16, [der_encode_ObjectIdentifier(?'id-stritzinger-grispProdDate'),
               der_encode_GeneralizedTime(maps:get(grisp_prod_date, GrispMeta))]}]}).


decode_grisp_meta(DER) ->
    {{16, Attrs}, <<>>} = asn1rt_nif:decode_ber_tlv(DER),
    maps:from_list([decode_grisp_meta_attr(Attr) || Attr <- Attrs]).


decode_grisp_meta_attr({16, [{6, OID},{22, IA5String}]}) ->
    {map_grisp_meta(der_decode_ObjectIdentifier(OID)), der_decode_IA5String(IA5String)};
decode_grisp_meta_attr({16, [{6, OID},{2, Integer}]}) ->
    {map_grisp_meta(der_decode_ObjectIdentifier(OID)), der_decode_Integer(Integer)};
decode_grisp_meta_attr({16, [{6, OID},{24, GeneralizedTime}]}) ->
    {map_grisp_meta(der_decode_ObjectIdentifier(OID)), der_decode_GeneralizedTime(GeneralizedTime)}.


map_grisp_meta(?'id-stritzinger-grispVersion')      -> grisp_version;
map_grisp_meta(?'id-stritzinger-grispSerial')       -> grisp_serial;
map_grisp_meta(?'id-stritzinger-grispPcbVersion')   -> grisp_pcb_version;
map_grisp_meta(?'id-stritzinger-grispPcbVariant')   -> grisp_pcb_variant;
map_grisp_meta(?'id-stritzinger-grispBatch')        -> grisp_batch;
map_grisp_meta(?'id-stritzinger-grispProdDate')     -> grisp_prod_date.


add_years({Date, _} = TS, Years) when is_tuple(Date) ->
    do_add_years(TS, Years);
add_years(UTCorGeneralTime, Years) ->
    TS = utc_or_general_time_to_ts(UTCorGeneralTime),
    do_add_years(TS, Years).


do_add_years(TS, Years) ->
    Secs = calendar:datetime_to_gregorian_seconds(TS),
    SecsToAdd = 60 * 60 * 24 * 365 * Years,
    TSAdd = calendar:gregorian_seconds_to_datetime(Secs + SecsToAdd),
    ts_to_utc_or_general_time(TSAdd).


compress(Cert, TemplateId, ChainId) ->
    TBS = Cert#'OTPCertificate'.tbsCertificate,
    CompDate = compress_date(TBS#'OTPTBSCertificate'.validity),
    CompSig = compress_sig(Cert#'OTPCertificate'.signature),
    <<CompSig:64/binary, CompDate:3/binary,
      0:16, TemplateId:4, ChainId:4, 0:16>>.


compress_sig(Sig) when byte_size(Sig) =:= 64 ->
    Sig;    %% was not DER encoded
compress_sig(Sig) ->
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', Sig),
    <<R:32/big-unsigned-integer-unit:8, S:32/big-unsigned-integer-unit:8>>.


compress_date(#'Validity'{notBefore = NotBefore} = Validity) ->
    {Year, Month, Day, Hour} = create_date_vars(NotBefore),
    ExpireYears = calc_expire_years(Validity),
    %% always assume utcTime here
    <<(Year - 2000):1/unsigned-integer-unit:5,
      Month:1/unsigned-integer-unit:4,
      Day:1/unsigned-integer-unit:5,
      Hour:1/unsigned-integer-unit:5,
      ExpireYears:1/unsigned-integer-unit:5>>.


decompress(TBS, <<CompSig:64/binary, CompDate:3/binary, _:5/binary>>) ->
    Validity = decompress_date(CompDate),
    Sig = decompress_sig(CompSig),
    #'OTPCertificate'{
        tbsCertificate = TBS#'OTPTBSCertificate'{validity = Validity},
        signatureAlgorithm = TBS#'OTPTBSCertificate'.signature,
        signature = Sig
    }.


decompress_sig(<<R:32/big-unsigned-integer-unit:8, S:32/big-unsigned-integer-unit:8>>) ->
    public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = R, s = S}).


decompress_date(<<Year:1/unsigned-integer-unit:5,
                  Month:1/unsigned-integer-unit:4,
                  Day:1/unsigned-integer-unit:5,
                  Hour:1/unsigned-integer-unit:5,
                  ExpireYears:1/unsigned-integer-unit:5>>) ->
    %% always utcTime
    TS = {{Year + 2000, Month, Day}, {Hour, 0, 0}},
    NotBefore = ts_to_utc_or_general_time(TS),
    NotAfter =
        case ExpireYears of
            0 ->
                ?MAX_NOT_AFTER;
            _ ->
                add_years(NotBefore, ExpireYears)
        end,
    #'Validity'{notBefore = NotBefore, notAfter = NotAfter}.


print(#'OTPCertificate'{} = Cert) ->
    io:format("~s", [encode_pem(Cert)]).

distinguished_name(Map) when is_map(Map) ->
    {rdnSequence, [
        lists:map(fun attribute_type_and_value/1, maps:to_list(Map))
                  ]}.

%%%%%%%%%%%%%%
%% HELPER
%%%%%%%%%%%%%%

%% There's no way to DER encode standard types using
%% standard modules.
%% We have to use alternative types available in public_key,
%% or the internal module 'OTP-PKIX'.

-if(?OTP_RELEASE >= 28).

%% CRLNumber is derived from Integer
der_encode_Integer(Int) ->
    <<T:8, _L:8, V/binary>> = public_key:der_encode('CRLNumber', Int),
    {T, V}.

der_decode_Integer(DER) ->
    public_key:der_decode('CRLNumber', DER).

%% InvalidityDate is derived from GeneralizedTime
der_encode_GeneralizedTime({{Year, Month, Day}, _}) ->
    TimeString = lists:flatten([string:right(integer_to_list(Int), Pad, $0) ||
                                {Int, Pad} <- [{Year, 4}, {Month, 2}, {Day, 2}]])
                               ++ [48,48,48,48,48,48,90],
    <<T:8, _L:8, V/binary>> = public_key:der_encode('InvalidityDate', TimeString),
    {T, V}.

der_decode_GeneralizedTime(DER) ->
    [Y1,Y2,Y3,Y4,
     M1,M2,
     D1,D2,
     H1,H2,
     48,48,48,48,90] = public_key:der_decode('InvalidityDate', DER),
    {{list_to_integer([Y1,Y2,Y3,Y4]),
      list_to_integer([M1,M2]),
      list_to_integer([D1,D2])},
     {list_to_integer([H1,H2]), 0, 0}}.

%% OTPDisplayText can be used to encode a IA5String
der_encode_IA5String(String) ->
    {ok, Bytes} = 'OTP-PKIX':encode('OTPDisplayText', {ia5String, String}),
    <<T:8, _L:8, V/binary>> = Bytes,
    {T, V}.
der_decode_IA5String(DER) ->
    {ok, {ia5String, String}} = 'OTP-PKIX':decode('OTPDisplayText', DER),
    String.

%% CertPolicyId is derived from ObjectIdentifier
der_encode_ObjectIdentifier(OId) ->
    {ok, Bytes} = 'OTP-PKIX':encode('CertPolicyId', OId),
    <<T:8, _L:8, V/binary>> = Bytes,
    {T, V}.

der_decode_ObjectIdentifier(DER) ->
    {ok, OId} = 'OTP-PKIX':decode('CertPolicyId', DER),
    OId.

-else.
%% Keeping backward compatibility with OTP 27 and earlier versions

%% There's no way to DER encode standard types using
%% standard modules, hence use undocumented 'OTP-PUB-KEY'
%% and some hackery

%% CertificateSerialNumber is derived from Integer
der_encode_Integer(Int) ->
    <<T:8, _L:8, V/binary>> =
        element(2, 'OTP-PUB-KEY':encode('CertificateSerialNumber', Int)),
    {T, V}.

der_decode_Integer(DER) ->
    element(2, 'OTP-PUB-KEY':decode('CertificateSerialNumber',
                                    <<2, (byte_size(DER)):8, DER/binary>>)).


%% InvalidityDate is derived from GeneralizedTime
der_encode_GeneralizedTime({{Year, Month, Day}, _}) ->
    TimeString = lists:flatten([string:right(integer_to_list(Int), Pad, $0) ||
                                {Int, Pad} <- [{Year, 4}, {Month, 2}, {Day, 2}]])
                               ++ [48,48,48,48,48,48,90],
    <<T:8, _L:8, V/binary>> =
        element(2, 'OTP-PUB-KEY':encode('InvalidityDate', TimeString)),
    {T, V}.

der_decode_GeneralizedTime(DER) ->
    [Y1,Y2,Y3,Y4,M1,M2,D1,D2,H1,H2,48,48,48,48,90] =
        element(2, 'OTP-PUB-KEY':decode('InvalidityDate',
                                        <<24, (byte_size(DER)):8, DER/binary>>)),
    {{list_to_integer([Y1,Y2,Y3,Y4]),
      list_to_integer([M1,M2]),
      list_to_integer([D1,D2])},
     {list_to_integer([H1,H2]), 0, 0}}.


%% EmailAddress is derived from IA5String
der_encode_IA5String(String) ->
    <<T:8, _L:8, V/binary>> =
        element(2, 'OTP-PUB-KEY':encode('EmailAddress', String)),
    {T, V}.

der_decode_IA5String(DER) ->
    element(2, 'OTP-PUB-KEY':decode('EmailAddress',
                                    <<22, (byte_size(DER)):8, DER/binary>>)).


%% CertPolicyId is derived from ObjectIdentifier
der_encode_ObjectIdentifier(Id) ->
    <<T:8, _L:8, V/binary>> =
        element(2, 'OTP-PUB-KEY':encode('CertPolicyId', Id)),
    {T, V}.

der_decode_ObjectIdentifier(DER) ->
    element(2, 'OTP-PUB-KEY':decode('CertPolicyId',
                                    <<6, (byte_size(DER)):8, DER/binary>>)).

-endif.

ext_authKeyId(#'OTPCertificate'{tbsCertificate = TBS}) ->
    SerialNumber = TBS#'OTPTBSCertificate'.serialNumber,
    RDNSequence = TBS#'OTPTBSCertificate'.issuer,
    Extensions = TBS#'OTPTBSCertificate'.extensions,
    #'Extension'{extnValue = SubjectKeyId} =
        lists:keyfind(?'id-ce-subjectKeyIdentifier', 2, Extensions),
    #'Extension'{
       extnID = ?'id-ce-authorityKeyIdentifier',
       extnValue =
        #'AuthorityKeyIdentifier'{
            keyIdentifier = SubjectKeyId,
            authorityCertIssuer = [{directoryName, RDNSequence}],
            authorityCertSerialNumber = SerialNumber}
      }.


ext_subKeyId(PubKeyBlob) ->
    #'Extension'{
       extnID = ?'id-ce-subjectKeyIdentifier',
       extnValue = crypto:hash(sha, PubKeyBlob)}.


%% see RFC5280 4.2.1.3
%% for CAs the extension SHOULD be critical
ext_keyUsage(UsageList) ->
    #'Extension'{
       extnID = ?'id-ce-keyUsage',
       extnValue = UsageList,
       critical = lists:member(keyCertSign, UsageList)}.


ext_extKeyUsage(client) ->
    #'Extension'{
       extnID = ?'id-ce-extKeyUsage',
       extnValue = [?'id-kp-clientAuth']};
ext_extKeyUsage(server) ->
    #'Extension'{
       extnID = ?'id-ce-extKeyUsage',
       extnValue = [?'id-kp-serverAuth']}.


%% see RFC5280 4.2.1.9
%% for CAs this extension MUST be critical, also
%% we don't care about validation path lengths
ext_isCa(IsCA) ->
    #'Extension'{
       extnID = ?'id-ce-basicConstraints',
       extnValue = #'BasicConstraints'{cA = IsCA},
       critical = IsCA}.


calc_expire_years(#'Validity'{notAfter = ?MAX_NOT_AFTER}) ->
    0;  %% no expiration
calc_expire_years(#'Validity'{notBefore = NotBefore, notAfter = NotAfter}) ->
    TS1 = utc_or_general_time_to_ts(NotBefore),
    TS2 = utc_or_general_time_to_ts(NotAfter),
    {Days, Hours} = calendar:time_difference(TS1, TS2),
    ExpireYears = Days div 365,
    case {ExpireYears < 32, Days rem 365, Hours} of
        {true, 0, {0, 0, 0}} ->
            ExpireYears;
        {C1, C2, C3} ->
            throw({error, {validity_broken, {C1, C2, C3}}})
    end.


ts_to_utc_or_general_time({{Year, Month, Day}, {Hour, 0, 0}}) when Year > 2049 ->
    {generalTime,
     lists:flatten([string:right(integer_to_list(Int), Pad, $0) ||
                    {Int, Pad} <- [{Year, 4}, {Month, 2}, {Day, 2}, {Hour, 2}]])
     ++ [48,48,48,48,90]};
ts_to_utc_or_general_time({{Year, Month, Day}, {Hour, 0, 0}}) ->
    {utcTime,
     lists:flatten([string:right(integer_to_list(Int), 2, $0) ||
                    Int <- [Year - 2000, Month, Day, Hour]])
     ++ [48,48,48,48,90]}.


utc_or_general_time_to_ts(UTCorGeneralTime) ->
    {Year, Month, Day, Hour} = create_date_vars(UTCorGeneralTime),
    {{Year, Month, Day}, {Hour, 0, 0}}.


create_date_vars({utcTime, [Y1,Y2,M1,M2,D1,D2,H1,H2,48,48,48,48,90]}) ->
    Year =  list_to_integer([Y1,Y2]) + 2000,
    Month = list_to_integer([M1,M2]),
    Day =   list_to_integer([D1,D2]),
    Hour =  list_to_integer([H1,H2]),
    {Year, Month, Day, Hour};
create_date_vars({generalTime, [Y1,Y2,Y3,Y4,M1,M2,D1,D2,H1,H2,48,48,48,48,90]}) ->
    Year =  list_to_integer([Y1,Y2,Y3,Y4]),
    Month = list_to_integer([M1,M2]),
    Day =   list_to_integer([D1,D2]),
    Hour =  list_to_integer([H1,H2]),
    {Year, Month, Day, Hour}.


build_cert_from_tbs(TBS,
                    <<R:32/big-unsigned-integer-unit:8,
                      S:32/big-unsigned-integer-unit:8>>) ->
    Sig = #'ECDSA-Sig-Value'{r = R, s = S},
    DERSig = public_key:der_encode('ECDSA-Sig-Value', Sig),
    #'OTPCertificate'{
       tbsCertificate = TBS,
       signatureAlgorithm = TBS#'OTPTBSCertificate'.signature,
       signature = DERSig
    }.


attribute_type_and_value({Key, Value}) ->
    Type = attribute_type(Key),
    AttrValue = case Type of
                    ?'id-at-dnQualifier'    -> Value;  %% printableString
                    ?'id-at-countryName'    -> Value;  %% printableString
                    ?'id-at-serialNumber'   -> Value;  %% printableString
                    ?'id-emailAddress'      -> Value;  %% ia5String
                    ?'id-domainComponent'   -> Value;  %% ia5String
                    _ -> {utf8String, Value}
                end,
    #'AttributeTypeAndValue'{
       type  = Type,
       value = AttrValue
    }.

attribute_type(Type) when Type =:= 'id-at-name';
                          Type =:= 'name';
                          Type =:= "name" ->
    ?'id-at-name';
attribute_type(Type) when Type =:= 'id-at-surname';
                          Type =:= 'surname';
                          Type =:= 'SN';
                          Type =:= "surname";
                          Type =:= "SN" ->
    ?'id-at-surname';
attribute_type(Type) when Type =:= 'id-at-givenName';
                          Type =:= 'givenName';
                          Type =:= 'GN';
                          Type =:= "givenName";
                          Type =:= "GN" ->
    ?'id-at-givenName';
attribute_type(Type) when Type =:= 'id-at-initials';
                          Type =:= 'initials';
                          Type =:= "initials" ->
    ?'id-at-initials';
attribute_type(Type) when Type =:= 'id-at-generationQualifier';
                          Type =:= 'generationQualifier';
                          Type =:= "generationQualifier" ->
    ?'id-at-generationQualifier';
attribute_type(Type) when Type =:= 'id-at-commonName';
                          Type =:= 'commonName';
                          Type =:= 'CN';
                          Type =:= "commonName";
                          Type =:= "CN" ->
    ?'id-at-commonName';
attribute_type(Type) when Type =:= 'id-at-localityName';
                          Type =:= 'localityName';
                          Type =:= 'L';
                          Type =:= "localityName";
                          Type =:= "L" ->
    ?'id-at-localityName';
attribute_type(Type) when Type =:= 'id-at-stateOrProvinceName';
                          Type =:= 'stateOrProvinceName';
                          Type =:= 'ST';
                          Type =:= "stateOrProvinceName";
                          Type =:= "ST" ->
    ?'id-at-stateOrProvinceName';
attribute_type(Type) when Type =:= 'id-at-organizationName';
                          Type =:= 'organizationName';
                          Type =:= 'O';
                          Type =:= "organizationName";
                          Type =:= "O" ->
    ?'id-at-organizationName';
attribute_type(Type) when Type =:= 'id-at-organizationalUnitName';
                          Type =:= 'organizationalUnitName';
                          Type =:= 'OU';
                          Type =:= "organizationalUnitName";
                          Type =:= "OU" ->
    ?'id-at-organizationalUnitName';
attribute_type(Type) when Type =:= 'id-at-title';
                          Type =:= 'title';
                          Type =:= "title" ->
    ?'id-at-title';
attribute_type(Type) when Type =:= 'id-at-dnQualifier';
                          Type =:= 'dnQualifier';
                          Type =:= "dnQualifier" ->
    ?'id-at-dnQualifier';
attribute_type(Type) when Type =:= 'id-at-countryName';
                          Type =:= 'countryName';
                          Type =:= 'C';
                          Type =:= "countryName";
                          Type =:= "C" ->
    ?'id-at-countryName';
attribute_type(Type) when Type =:= 'id-at-serialNumber';
                          Type =:= 'serialNumber';
                          Type =:= "serialNumber" ->
    ?'id-at-serialNumber';
attribute_type(Type) when Type =:= 'id-at-pseudonym';
                          Type =:= 'pseudonym';
                          Type =:= "pseudonym" ->
    ?'id-at-pseudonym';
attribute_type(Type) when Type =:= 'id-domainComponent';
                          Type =:= 'domainComponent';
                          Type =:= "domainComponent" ->
    ?'id-domainComponent';
attribute_type(Type) when Type =:= 'id-emailAddress';
                          Type =:= 'emailAddress';
                          Type =:= "emailAddress" ->
    ?'id-emailAddress';
attribute_type(Type) -> Type.
