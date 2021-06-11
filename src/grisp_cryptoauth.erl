-module(grisp_cryptoauth).

%% Convenience wrappers,
%% using default config
-export([device_info/0,
         config_locked/0,
         data_locked/0,
         slot_locked/1,
         serial_number/0,
         read_config/0,
         write_config/0,
         lock_config/0,
         lock_data/0,
         lock_slot/1,
         gen_private_key/1,
         gen_public_key/1,
         sign/2,
         verify_extern/3,
         verify_stored/3]).

%% Convenience wrappers,
%% using custom config
-export([device_info/1,
         config_locked/1,
         data_locked/1,
         slot_locked/2,
         serial_number/1,
         read_config/1,
         write_config/1,
         lock_config/1,
         lock_data/1,
         lock_slot/2,
         gen_private_key/2,
         gen_public_key/2,
         sign/3,
         verify_extern/4,
         verify_stored/4]).

-define(APP, grisp_cryptoauth).

-define(DEFAULT_DEVICE, 'ATECC608B').

-define(DEFAULT_CONFIG,
        #{type => ?DEFAULT_DEVICE,
          i2c_bus => 1,
          i2c_address => 16#6C}).

-define(VALID_DEVICES,
        ['ATECC508A', 'ATECC608A', 'ATECC608B']).


%% ---------------
%% Config handling
%% ---------------

validate_config(Config) ->
    lists:member(maps:get(type, Config, ?DEFAULT_DEVICE), ?VALID_DEVICES).

default_config() ->
    case application:get_env(?APP, device) of
        undefined ->
            ?DEFAULT_CONFIG;
        {ok, Config} ->
            case validate_config(Config) of
                true ->
                    maps:merge(?DEFAULT_CONFIG, Config);
                false ->
                    exit({badarg, invalid_config})
            end
    end.

build_config(Config) ->
    case validate_config(Config) of
        true ->
            maps:merge(default_config(), Config);
        false ->
            exit({badarg, invalid_config})
    end.


%% --------------------
%% Convenience wrappers
%% --------------------

device_info() ->
    grisp_cryptoauth_nif:device_info(default_config()).

device_info(Config) ->
    grisp_cryptoauth_nif:device_info(build_config(Config)).

config_locked() ->
    grisp_cryptoauth_nif:config_locked(default_config()).

config_locked(Config) ->
    grisp_cryptoauth_nif:config_locked(build_config(Config)).

data_locked() ->
    grisp_cryptoauth_nif:data_locked(default_config()).

data_locked(Config) ->
    grisp_cryptoauth_nif:data_locked(build_config(Config)).

slot_locked(SlotIdx) ->
    grisp_cryptoauth_nif:slot_locked(default_config(), SlotIdx).

slot_locked(Config, SlotIdx) ->
    grisp_cryptoauth_nif:slot_locked(build_config(Config), SlotIdx).

serial_number() ->
    grisp_cryptoauth_nif:serial_number(default_config()).

serial_number(Config) ->
    grisp_cryptoauth_nif:serial_number(build_config(Config)).

read_config() ->
    grisp_cryptoauth_nif:read_config(default_config()).

read_config(Config) ->
    grisp_cryptoauth_nif:read_config(build_config(Config)).

write_config() ->
    grisp_cryptoauth_nif:write_config(default_config()).

write_config(Config) ->
    grisp_cryptoauth_nif:write_config(build_config(Config)).

lock_config() ->
    grisp_cryptoauth_nif:lock_config(default_config()).

lock_config(Config) ->
    grisp_cryptoauth_nif:lock_config(build_config(Config)).

lock_data() ->
    grisp_cryptoauth_nif:lock_data(default_config()).

lock_data(Config) ->
    grisp_cryptoauth_nif:lock_data(build_config(Config)).

lock_slot(SlotIdx) ->
    grisp_cryptoauth_nif:lock_slot(default_config(), SlotIdx).

lock_slot(Config, SlotIdx) ->
    grisp_cryptoauth_nif:lock_slot(build_config(Config), SlotIdx).

gen_private_key(SlotIdx) ->
    grisp_cryptoauth_nif:gen_private_key(default_config(), SlotIdx).

gen_private_key(Config, SlotIdx) ->
    grisp_cryptoauth_nif:gen_private_key(build_config(Config), SlotIdx).

gen_public_key(SlotIdx) ->
    grisp_cryptoauth_nif:gen_public_key(default_config(), SlotIdx).

gen_public_key(Config, SlotIdx) ->
    grisp_cryptoauth_nif:gen_public_key(build_config(Config), SlotIdx).

sign(SlotIdx, Msg) ->
    grisp_cryptoauth_nif:sign(default_config(), SlotIdx, Msg).

sign(Config, SlotIdx, Msg) ->
    grisp_cryptoauth_nif:sign(build_config(Config), SlotIdx, Msg).

verify_extern(PubKey, Msg, Sig) ->
    grisp_cryptoauth_nif:verify_extern(default_config(), PubKey, Msg, Sig).

verify_extern(Config, PubKey, Msg, Sig) ->
    grisp_cryptoauth_nif:verify_extern(build_config(Config), PubKey, Msg, Sig).

verify_stored(SlotIdx, Msg, Sig) ->
    grisp_cryptoauth_nif:verify_stored(default_config(), SlotIdx, Msg, Sig).

verify_stored(Config, SlotIdx, Msg, Sig) ->
    grisp_cryptoauth_nif:verify_stored(build_config(Config), SlotIdx, Msg, Sig).
