-module(grisp_cryptoauth_cert).

-include_lib("public_key/include/public_key.hrl").

%% Public API
-export([compress/1,
         decompress/2,
         add_years/2]).

%% Testing
-export([compress_sig/1, decompress_sig/1,
         compress_date/1, decompress_date/1,
         calc_expire_years/1]).

-define(MAX_NOT_AFTER, {generalTime, "99991231235959Z"}).


add_years(UTCorGeneralTime, Years) ->
    TS = utc_or_general_time_to_ts(UTCorGeneralTime),
    Secs = calendar:datetime_to_gregorian_seconds(TS),
    SecsToAdd = 60 * 60 * 24 * 365 * Years,
    TSAdd = calendar:gregorian_seconds_to_datetime(Secs + SecsToAdd),
    ts_to_utc_or_general_time(TSAdd).


compress(Cert) ->
    TBS = Cert#'OTPCertificate'.tbsCertificate,
    CompDate = compress_date(TBS#'OTPTBSCertificate'.validity),
    CompSig = compress_sig(Cert#'OTPCertificate'.signature),
    <<CompSig:64/binary, CompDate:3/binary, 0:5/unit:8>>.


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


decompress(TBSCert, <<CompSig:64/binary, CompDate:3/binary, _:5/binary>>) ->
    Validity = decompress_date(CompDate),
    Sig = decompress_sig(CompSig),
    #'OTPCertificate'{
        tbsCertificate = TBSCert#'OTPTBSCertificate'{validity = Validity},
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


%%%%%%%%%%%%%%
%% HELPER
%%%%%%%%%%%%%%


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
