-module(grisp_cryptoauth).

%% Main API
-export([sign/2,
         sign/3,
         verify/3,
         verify/4,
         public_key/1,
         public_key/2,
         refresh/1,
         refresh/2,
         setup/1,
         check_device/0,
         check_device/1,
         device_info/0,
         device_info/1,
         write_cert/1,
         write_cert/2,
         read_cert/1,
         read_cert/2]).

-define(PRIMARY_PRIVATE_KEY, 0).
-define(SECONDARY_PRIVATE_KEY_1, 2).
-define(SECONDARY_PRIVATE_KEY_2, 3).
-define(SECONDARY_PRIVATE_KEY_3, 4).

-define(APP, grisp_cryptoauth).
-define(DEFAULT_DEVICE, 'ATECC608').
-define(VALID_DEVICES,
        ['ATECC508A', 'ATECC608A', 'ATECC608B', 'ATECC608']).
-define(DEFAULT_CONFIG,
        #{type => ?DEFAULT_DEVICE,
          i2c_bus => 1,
          i2c_address => 16#6C}).


%% ---------------
%% Main API
%% ---------------

sign(PrivKey, Msg) ->
    sign(PrivKey, Msg, #{}).

sign(primary, Msg, Config) ->
    do_sign(?PRIMARY_PRIVATE_KEY, Msg, Config);
sign(secondary_1, Msg, Config) ->
    do_sign(?SECONDARY_PRIVATE_KEY_1, Msg, Config);
sign(secondary_2, Msg, Config) ->
    do_sign(?SECONDARY_PRIVATE_KEY_2, Msg, Config);
sign(secondary_3, Msg, Config) ->
    do_sign(?SECONDARY_PRIVATE_KEY_3, Msg, Config).


verify(PubKey, Msg, Sig) ->
    verify(PubKey, Msg, Sig, #{}).

verify(primary, Msg, Sig, Config) ->
    do_verify(?PRIMARY_PRIVATE_KEY, Msg, Sig, Config);
verify(secondary_1, Msg, Sig, Config) ->
    do_verify(?SECONDARY_PRIVATE_KEY_1, Msg, Sig, Config);
verify(secondary_2, Msg, Sig, Config) ->
    do_verify(?SECONDARY_PRIVATE_KEY_2, Msg, Sig, Config);
verify(secondary_3, Msg, Sig, Config) ->
    do_verify(?SECONDARY_PRIVATE_KEY_3, Msg, Sig, Config);
verify(PubKey, Msg, Sig, Config) when is_binary(PubKey) or is_list(PubKey) ->
    do_verify(PubKey, Msg, Sig, Config).

public_key(PubKey) ->
    public_key(PubKey, #{}).

public_key(primary, Config) ->
    do_public_key(?PRIMARY_PRIVATE_KEY, Config);
public_key(secondary_1, Config) ->
    do_public_key(?SECONDARY_PRIVATE_KEY_1, Config);
public_key(secondary_2, Config) ->
    do_public_key(?SECONDARY_PRIVATE_KEY_2, Config);
public_key(secondary_3, Config) ->
    do_public_key(?SECONDARY_PRIVATE_KEY_3, Config).

refresh(PrivKey) ->
    refresh(PrivKey, #{}).

refresh(secondary_1, Config) ->
    do_refresh(?SECONDARY_PRIVATE_KEY_1, Config);
refresh(secondary_2, Config) ->
    do_refresh(?SECONDARY_PRIVATE_KEY_2, Config);
refresh(secondary_3, Config) ->
    do_refresh(?SECONDARY_PRIVATE_KEY_3, Config).


setup(Config) ->
    BuiltConfig = build_config(Config),
    case grisp_cryptoauth_nif:config_locked(BuiltConfig) of
        {ok, false} ->
            do_setup(BuiltConfig);
        {ok, true} ->
            {error, config_locked};
        Error ->
            Error
    end.


check_device() ->
    check_device(#{}).

check_device(Config) ->
    case grisp_cryptoauth_nif:device_info(Config) of
        {ok, DeviceType} ->
            case lists:member(DeviceType, ?VALID_DEVICES) of
                true ->
                    ok;
                false ->
                    {error, invalid_device}
            end;
        Error ->
            Error
    end.


device_info() ->
    device_info(#{}).

device_info(Config) ->
    BuiltConfig = build_config(Config),
    case check_device(BuiltConfig) of
        ok ->
            Info = generate_device_info(BuiltConfig),
            io:format("~s", [Info]);
        Error ->
            Error
    end.


write_cert(Cert) ->
    write_cert(Cert, #{}).

write_cert(Cert, Config) ->
    grisp_cryptoauth_nif:write_cert(build_config(Config), Cert).


read_cert(PubKey) ->
    read_cert(PubKey, #{}).

read_cert(PubKey, Config) ->
    grisp_cryptoauth_nif:read_cert(build_config(Config), PubKey).

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

do_sign(SlotIdx, Msg, Config) ->
    grisp_cryptoauth_nif:sign(build_config(Config), SlotIdx, crypto:hash(sha256, Msg)).

do_verify(PubKey, Msg, Sig, Config) when is_list(PubKey) ->
    do_verify(binary:list_to_bin(PubKey), Msg, Sig, Config);
do_verify(PubKey, Msg, Sig, Config) when is_binary(PubKey) ->
    grisp_cryptoauth_nif:verify_extern(build_config(Config), PubKey, crypto:hash(sha256, Msg), Sig);
do_verify(SlotIdx, Msg, Sig, Config) when is_integer(SlotIdx) ->
    BuiltConfig = build_config(Config),
    case grisp_cryptoauth_nif:gen_public_key(BuiltConfig, SlotIdx) of
        {ok, PubKey} ->
            grisp_cryptoauth_nif:verify_extern(BuiltConfig, PubKey, crypto:hash(sha256, Msg), Sig);
        Error ->
            Error
    end.

do_public_key(SlotIdx, Config) ->
    grisp_cryptoauth_nif:gen_public_key(build_config(Config), SlotIdx).

do_refresh(SlotIdx, Config) ->
    grisp_cryptoauth_nif:gen_private_key(build_config(Config), SlotIdx).

do_setup(Config) ->
    grisp_cryptoauth_nif:write_config(Config),
    grisp_cryptoauth_nif:lock_config(Config),
    PrivKeys = [?PRIMARY_PRIVATE_KEY, ?SECONDARY_PRIVATE_KEY_1, ?SECONDARY_PRIVATE_KEY_2, ?SECONDARY_PRIVATE_KEY_3],
    [grisp_cryptoauth_nif:gen_private_key(Config, SlotIdx) || SlotIdx <- PrivKeys],
    grisp_cryptoauth_nif:lock_data(Config),
    ok.

generate_device_info(Config) ->
    {ok, DeviceType} = grisp_cryptoauth_nif:device_info(Config),
    {ok, SerialNumber} = grisp_cryptoauth_nif:serial_number(Config),
    {ok, IsConfigLocked} = grisp_cryptoauth_nif:config_locked(Config),
    {ok, IsDataLocked} = grisp_cryptoauth_nif:data_locked(Config),
    Header = "GRiSP2 Secure Element",
    Sep = "=====================",
    DeviceTypeText = ["Type: ", atom_to_binary(DeviceType, latin1)],
    SerialNumberText = ["Serial Number: ", bin_to_hex(SerialNumber)],
    ConfigLockedText = ["Config Locked: ", atom_to_binary(IsConfigLocked, latin1)],
    DataLockedText = ["Data Locked: ", atom_to_binary(IsDataLocked, latin1)],
    io_lib:format("~s~n~s~n~s~n~s~n~s~n~s~n",
              [Header, Sep, DeviceTypeText, SerialNumberText, ConfigLockedText, DataLockedText]).

bin_to_hex(Bin) ->
    lists:droplast(lists:flatten([[io_lib:format("~2.16.0B",[X]), " "] || <<X:8>> <= Bin ])).
