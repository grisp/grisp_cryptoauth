-module(grisp_cryptoauth).

%% Main API
-export([sign/2,
         sign_fun/1,
         verify/3,
         public_key/1,
         refresh_key/1,
         read_cert/2,
         write_cert/3,
         device_info/0,
         setup_device/0,
         random_bytes/1]).

%% Use for testing
%% without API server
-export([init/0,
         init/1,
         sleep/0,
         sleep/1,
         sign/3,
         verify/4,
         public_key/2,
         refresh_key/2,
         read_cert/3,
         write_cert/4,
         device_info/1,
         setup_device/1,
         random_bytes/2]).


-include_lib("public_key/include/public_key.hrl").


-define(PRIMARY_PRIVATE_KEY, 0).
-define(SECONDARY_PRIVATE_KEY_1, 2).
-define(SECONDARY_PRIVATE_KEY_2, 3).
-define(SECONDARY_PRIVATE_KEY_3, 4).
-define(PRIMARY_CERT, 10).
-define(SECONDARY_CERT, 12).
-define(DEFAULT_TEMPLATES, [{{0, 0}, test}]).

-define(APP, grisp_cryptoauth).
-define(DEFAULT_DEVICE, 'ATECC608').
-define(VALID_DEVICES,
        ['ATECC508A', 'ATECC608A', 'ATECC608B', 'ATECC608']).
-define(DEFAULT_CONFIG,
        #{type => ?DEFAULT_DEVICE,
          i2c_bus => 0,
          i2c_address => 16#6C}).

-define(API_SERVER, grisp_cryptoauth_api_server).
-define(CALL_API_SERVER(Args), gen_server:call(?API_SERVER, {?FUNCTION_NAME, Args})).

%% ---------------
%% Main API
%% ---------------

init() ->
    init(#{}).

init(Config) ->
    BuiltConfig = build_config(Config),
    grisp_cryptoauth_drv:init_device(BuiltConfig).


sleep() ->
    ?CALL_API_SERVER([]).

sleep(Context) ->
    grisp_cryptoauth_drv:sleep_device(Context).


sign(Type, Msg) ->
    ?CALL_API_SERVER([Type, Msg]).

sign(Context, primary, Msg) ->
    do_sign(Context, ?PRIMARY_PRIVATE_KEY, Msg);
sign(Context, secondary_1, Msg) ->
    do_sign(Context, ?SECONDARY_PRIVATE_KEY_1, Msg);
sign(Context, secondary_2, Msg) ->
    do_sign(Context, ?SECONDARY_PRIVATE_KEY_2, Msg);
sign(Context, secondary_3, Msg) ->
    do_sign(Context, ?SECONDARY_PRIVATE_KEY_3, Msg).


%% Used within patched ssl library for private (primary) key:
%% {key, #{algorithm => ecdsa, sign_fun => {grisp_cryptoauth, sign_fun}}}
sign_fun(Msg) ->
    {ok, Sig} = sign(primary, Msg),
    <<R:32/big-unsigned-integer-unit:8, S:32/big-unsigned-integer-unit:8>> = Sig,
    public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = R, s = S}).


verify(Type, Msg, Sig) ->
    ?CALL_API_SERVER([Type, Msg, Sig]).

verify(Context, primary, Msg, Sig) ->
    do_verify(Context, ?PRIMARY_PRIVATE_KEY, Msg, Sig);
verify(Context, secondary_1, Msg, Sig) ->
    do_verify(Context, ?SECONDARY_PRIVATE_KEY_1, Msg, Sig);
verify(Context, secondary_2, Msg, Sig) ->
    do_verify(Context, ?SECONDARY_PRIVATE_KEY_2, Msg, Sig);
verify(Context, secondary_3, Msg, Sig) ->
    do_verify(Context, ?SECONDARY_PRIVATE_KEY_3, Msg, Sig);
verify(Context, PubKey, Msg, Sig) when is_binary(PubKey) or is_list(PubKey) ->
    do_verify(Context, PubKey, Msg, Sig).


public_key(Type) ->
    ?CALL_API_SERVER([Type]).

public_key(undefined, Type) ->
    public_key(Type);
public_key(Context, primary) ->
    do_public_key(Context, ?PRIMARY_PRIVATE_KEY);
public_key(Context, secondary_1) ->
    do_public_key(Context, ?SECONDARY_PRIVATE_KEY_1);
public_key(Context, secondary_2) ->
    do_public_key(Context, ?SECONDARY_PRIVATE_KEY_2);
public_key(Context, secondary_3) ->
    do_public_key(Context, ?SECONDARY_PRIVATE_KEY_3).


refresh_key(Type) ->
    ?CALL_API_SERVER([Type]).

refresh_key(Context, secondary_1) ->
    do_refresh_key(Context, ?SECONDARY_PRIVATE_KEY_1);
refresh_key(Context, secondary_2) ->
    do_refresh_key(Context, ?SECONDARY_PRIVATE_KEY_2);
refresh_key(Context, secondary_3) ->
    do_refresh_key(Context, ?SECONDARY_PRIVATE_KEY_3).


setup_device() ->
    ?CALL_API_SERVER([]).

setup_device(Context) ->
    case grisp_cryptoauth_drv:config_locked(Context) of
        {ok, false} ->
            do_setup_device(Context);
        {ok, true} ->
            {error, config_locked};
        Error ->
            Error
    end.


device_info() ->
    ?CALL_API_SERVER([]).

device_info(Context) ->
    io:format("~s", [generate_device_info(Context)]).

%% This API will be removed on the long run
read_cert(Type, DerOrPlain) ->
    ?CALL_API_SERVER([Type, DerOrPlain]).

%% This API will be removed on the long run
read_cert(Context, Type, DerOrPlain) when is_atom(Type) ->
    Templates = application:get_env(grisp_cryptoauth, templates, ?DEFAULT_TEMPLATES),
    read_cert(Context, Type, Templates, DerOrPlain);
read_cert(Type, Templates, DerOrPlain) ->
    ?CALL_API_SERVER([Type, Templates, DerOrPlain]).

read_cert(Context, primary, Templates, DerOrPlain) ->
    read_cert(Context, ?PRIMARY_CERT, Templates, DerOrPlain);
read_cert(Context, secondary, Templates, DerOrPlain) ->
    read_cert(Context, ?SECONDARY_CERT, Templates, DerOrPlain);
read_cert(Context, Slot, Templates, DerOrPlain) when is_integer(Slot) ->
    {ok, CompCert} = grisp_cryptoauth_drv:read_comp_cert(Context, Slot),
    <<TemplateId:4, ChainId:4>> = <<(binary:at(CompCert, 69))>>,
    case lists:keyfind({TemplateId, ChainId}, 1, Templates) of
        false ->
            {error, {undefined, {TemplateId, ChainId}}};
        {_, TBSFunName} ->
            TBS = case TBSFunName of
                      {Mod, Fun} ->
                          Mod:Fun(Context);
                      _ ->
                          grisp_cryptoauth_template:TBSFunName(Context)
                  end,
            Cert = grisp_cryptoauth_cert:decompress(TBS, CompCert),
            case DerOrPlain of
                plain ->
                    Cert;
                der ->
                    public_key:pkix_encode('OTPCertificate', Cert, otp)
            end
    end.


write_cert(Type, TBSFunName, Cert) ->
    ?CALL_API_SERVER([Type, TBSFunName, Cert]).

write_cert(Context, primary, TBSFunName, Cert) ->
    write_cert(Context, ?PRIMARY_CERT, TBSFunName, Cert);
write_cert(Context, secondary, TBSFunName, Cert) ->
    write_cert(Context, ?SECONDARY_CERT, TBSFunName, Cert);
write_cert(Context, Slot, TBSFunName, Cert) when is_integer(Slot) ->
    Templates = application:get_env(grisp_cryptoauth, templates, ?DEFAULT_TEMPLATES),
    case lists:keyfind(TBSFunName, 2, Templates) of
        false ->
            {error, {undefined, TBSFunName}};
        {{TemplateId, ChainId}, _} ->
            CompCert = grisp_cryptoauth_cert:compress(Cert, TemplateId, ChainId),
            grisp_cryptoauth_drv:write_comp_cert(Context, Slot, CompCert)
    end.


random_bytes(N) ->
    ?CALL_API_SERVER([N]).

random_bytes(Context, N) ->
    <<RandBytes:N/binary, _/binary>> = random_bytes(Context, (N div 32) + 1, []),
    {ok, RandBytes}.

random_bytes(_Context, 0, Acc) ->
    iolist_to_binary(Acc);
random_bytes(Context, ChunksN, Acc) ->
    %% Generate a 32 byte chunk
    {ok, RandBytes} = grisp_cryptoauth_drv:gen_random_bytes(Context),
    random_bytes(Context, ChunksN-1, [RandBytes | Acc]).


%% ---------------
%% Config handling
%% ---------------

validate_config(Config) ->
    lists:member(maps:get(type, Config, ?DEFAULT_DEVICE), ?VALID_DEVICES).

default_config() ->
    maps:merge(?DEFAULT_CONFIG, application:get_env(?APP, device, #{})).

build_config(Config) ->
    MergedConfig = maps:merge(default_config(), Config),
    case validate_config(MergedConfig) of
        true ->
            MergedConfig;
        false ->
            exit({badarg, invalid_config})
    end.


%% ---------------
%% Helpers
%% ---------------

do_sign(Context, SlotIdx, Msg) ->
    grisp_cryptoauth_drv:sign(Context, SlotIdx, crypto:hash(sha256, Msg)).

do_verify(Context, PubKey, Msg, Sig) when is_list(PubKey) ->
    do_verify(Context, binary:list_to_bin(PubKey), Msg, Sig);
do_verify(Context, PubKey, Msg, Sig) when is_binary(PubKey) ->
    grisp_cryptoauth_drv:verify_extern(Context, PubKey, crypto:hash(sha256, Msg), Sig);
do_verify(Context, SlotIdx, Msg, Sig) when is_integer(SlotIdx) ->
    case grisp_cryptoauth_drv:gen_public_key(Context, SlotIdx) of
        {ok, PubKey} ->
            grisp_cryptoauth_drv:verify_extern(Context, PubKey, crypto:hash(sha256, Msg), Sig);
        Error ->
            Error
    end.

do_public_key(Context, SlotIdx) ->
    case grisp_cryptoauth_drv:gen_public_key(Context, SlotIdx) of
        {ok, PubKey} ->
                %% 0x04 means uncompressed (both X and
                %% Y integers), not just the X integer
                {ok, <<16#04, PubKey:64/binary>>};
        Error ->
                Error
    end.

do_refresh_key(Context, SlotIdx) ->
    grisp_cryptoauth_drv:gen_private_key(Context, SlotIdx).

do_setup_device(Context) ->
    ok = grisp_cryptoauth_drv:write_config(Context),
    ok = grisp_cryptoauth_drv:lock_config(Context),
    {ok, _} = grisp_cryptoauth_drv:gen_private_key(Context, ?PRIMARY_PRIVATE_KEY),
    {ok, _} = grisp_cryptoauth_drv:gen_private_key(Context, ?SECONDARY_PRIVATE_KEY_1),
    {ok, _} = grisp_cryptoauth_drv:gen_private_key(Context, ?SECONDARY_PRIVATE_KEY_2),
    {ok, _} = grisp_cryptoauth_drv:gen_private_key(Context, ?SECONDARY_PRIVATE_KEY_3),
    ok = grisp_cryptoauth_drv:lock_data(Context),
    ok.

generate_device_info(Context) ->
    {ok, DeviceType} = grisp_cryptoauth_drv:device_info(Context),
    {ok, SerialNumber} = grisp_cryptoauth_drv:serial_number(Context),
    {ok, IsConfigLocked} = grisp_cryptoauth_drv:config_locked(Context),
    {ok, IsDataLocked} = grisp_cryptoauth_drv:data_locked(Context),
    Header = "GRiSP2 Secure Element",
    Sep =    "=====================",
    DeviceTypeText =    ["Type: ", atom_to_binary(DeviceType, latin1)],
    SerialNumberText =  ["Serial Number: ", bin_to_hex(SerialNumber)],
    ConfigLockedText =  ["Config Locked: ", atom_to_binary(IsConfigLocked, latin1)],
    DataLockedText =    ["Data Locked: ", atom_to_binary(IsDataLocked, latin1)],
    io_lib:format("~s~n~s~n~s~n~s~n~s~n~s~n",
              [Header, Sep, DeviceTypeText, SerialNumberText, ConfigLockedText, DataLockedText]).

bin_to_hex(Bin) ->
    lists:droplast(lists:flatten([[io_lib:format("~2.16.0B",[X]), " "] || <<X:8>> <= Bin ])).
