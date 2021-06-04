-module(grisp_cryptoauth).

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
         gen_private_key/0,
         gen_public_key/0]).


device_info() ->
    grisp_cryptoauth_nif:device_info().

config_locked() ->
    grisp_cryptoauth_nif:config_locked().

data_locked() ->
    grisp_cryptoauth_nif:data_locked().

slot_locked(SlotIdx) ->
    grisp_cryptoauth_nif:slot_locked(SlotIdx).

serial_number() ->
    grisp_cryptoauth_nif:serial_number().

read_config() ->
    grisp_cryptoauth_nif:read_config().

write_config() ->
    grisp_cryptoauth_nif:write_config().

lock_config() ->
    grisp_cryptoauth_nif:lock_config().

lock_data() ->
    grisp_cryptoauth_nif:lock_data().

lock_slot(SlotIdx) ->
    grisp_cryptoauth_nif:lock_slot(SlotIdx).

gen_private_key() ->
    grisp_cryptoauth_nif:gen_private_key().

gen_public_key() ->
    grisp_cryptoauth_nif:gen_public_key().
