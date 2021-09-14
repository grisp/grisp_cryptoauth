-module(grisp_cryptoauth_cert).

-include_lib("public_key/include/public_key.hrl").

%% Public API
-export([decode_pem_file/1,
         decode_pem/1,
         encode_pem/1,
         sign/2,
         compress/3,
         decompress/2,
         print/1,
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
         calc_expire_years/1]).

-define(MAX_NOT_AFTER, {generalTime, "99991231235959Z"}).
-define('id-stritzinger-grispMeta', {1,3,6,1,4,1,4849,1}).


decode_pem_file(FilePath) ->
    decode_pem(element(2, file:read_file(FilePath))).


decode_pem(PEM) ->
    public_key:pkix_decode_cert(
      element(2, hd(public_key:pem_decode(PEM))), otp).


encode_pem(#'OTPCertificate'{} = Cert) ->
    public_key:pem_encode(
        [{'Certificate',
          public_key:pkix_encode('OTPCertificate', Cert, otp),
          not_encrypted}]).


sign(#'OTPTBSCertificate'{} = TBS, SignFun) when is_function(SignFun) ->
    DER = public_key:pkix_encode('OTPTBSCertificate', TBS, otp),
    %% expect DER enoded Signature here for now
    DERSig = SignFun(DER),
    #'OTPCertificate'{
       tbsCertificate = TBS,
       signatureAlgorithm = TBS#'OTPTBSCertificate'.signature,
       signature = DERSig};
sign(#'OTPTBSCertificate'{} = TBS, PrivateKey) ->
    public_key:pkix_decode_cert(
      public_key:pkix_sign(TBS, PrivateKey), otp);
sign({Mod, Fun}, SignFunOrPrivateKey) ->
    sign(Mod:Fun(), SignFunOrPrivateKey);
sign(Fun, SignFunOrPrivateKey) when is_atom(Fun) ->
    sign(grisp_cryptoauth_template:Fun(), SignFunOrPrivateKey).


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
    {T1,V1} = der_encode_IA5String(element(2, lists:keyfind(grisp_version, 1, GrispMeta))),
    {T2,V2} = der_encode_Integer(element(2, lists:keyfind(grisp_serial, 1, GrispMeta))),
    {T3,V3} = der_encode_IA5String(element(2, lists:keyfind(grisp_pcb_version, 1, GrispMeta))),
    {T4,V4} = der_encode_Integer(element(2, lists:keyfind(grisp_batch, 1, GrispMeta))),
    {T5,V5} = der_encode_GeneralizedTime(element(2, lists:keyfind(grisp_prod_date, 1, GrispMeta))),
    ToBeEncoded = [{T1,V1}, {T2,V2}, {T3,V3}, {T4,V4}, {T5,V5}],
    %% Encode all GRiSP meta data in a Sequence
    DER = asn1rt_nif:encode_ber_tlv({16, ToBeEncoded}),
    #'Extension'{
       extnID = ?'id-stritzinger-grispMeta',
       extnValue = DER}.


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


%%%%%%%%%%%%%%
%% HELPER
%%%%%%%%%%%%%%


%% There's no way to DER encode standard types using
%% standard modules, hence use undocumented 'OTP-PUB-KEY'
%% and some hackery

%% CertificateSerialNumber is derived from Integer
der_encode_Integer(Int) ->
    <<T:8, _L:8, V/binary>> =
        element(2, 'OTP-PUB-KEY':encode('CertificateSerialNumber', Int)),
    {T, V}.


%% InvalidityDate is derived from GeneralizedTime
der_encode_GeneralizedTime({{Year, Month, Day}, _}) ->
    TimeString = lists:flatten([string:right(integer_to_list(Int), Pad, $0) ||
                                {Int, Pad} <- [{Year, 4}, {Month, 2}, {Day, 2}]])
                               ++ [48,48,48,48,48,48,90],
    <<T:8, _L:8, V/binary>> =
        element(2, 'OTP-PUB-KEY':encode('InvalidityDate', TimeString)),
    {T, V}.


%% EmailAddress is derived from IA5String
der_encode_IA5String(String) ->
    <<T:8, _L:8, V/binary>> =
        element(2, 'OTP-PUB-KEY':encode('EmailAddress', String)),
    {T, V}.


ext_authKeyId(#'OTPCertificate'{tbsCertificate = TBS}) ->
    SerialNumber = TBS#'OTPTBSCertificate'.serialNumber,
    RDNSequence = TBS#'OTPTBSCertificate'.subject,
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


ext_keyUsage(UsageList) ->
    #'Extension'{
       extnID = ?'id-ce-keyUsage',
       extnValue = UsageList}.


ext_extKeyUsage(client) ->
    #'Extension'{
       extnID = ?'id-ce-extKeyUsage',
       extnValue = [?'id-kp-clientAuth']};
ext_extKeyUsage(server) ->
    #'Extension'{
       extnID = ?'id-ce-extKeyUsage',
       extnValue = [?'id-kp-serverAuth']}.


ext_isCa(IsCA) ->
    #'Extension'{
       extnID = ?'id-ce-basicConstraints',
       extnValue = #'BasicConstraints'{cA = IsCA}}.


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
