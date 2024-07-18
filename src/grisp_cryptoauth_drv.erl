-module(grisp_cryptoauth_drv).

-export([init_device/1,
         sleep_device/1,
         device_info/1,
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
         verify_stored/4,
         write_comp_cert/3,
         read_comp_cert/2,
         gen_random_bytes/1]).

-on_load(init/0).

-ifdef(EMULATE_CRYPTOAUTH).

init() -> ok.

-define(nif_stub,
    erlang:nif_error({nif_not_emulated,
                      module, ?MODULE,
                      function, {?FUNCTION_NAME, ?FUNCTION_ARITY},
                      line, ?LINE})).

init_device(_Config) -> {ok, emulated}.

-else. % EMULATE_CRYPTOAUTH not defined

init() ->
    SoName = case code:priv_dir(grisp_cryptoauth) of
        {error, bad_name} ->
            case filelib:is_dir(filename:join(["..", priv])) of
                true ->
                    filename:join(["..", priv, grisp_cryptoauth_drv]);
                _ ->
                    filename:join([priv, grisp_cryptoauth_drv])
            end;
        Dir ->
            filename:join(Dir, grisp_cryptoauth_drv)
    end,
    erlang:load_nif(SoName, 0).

-define(nif_stub,
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE})).

init_device(_)  ->          ?nif_stub.

-endif.

sleep_device(_)  ->         ?nif_stub.
device_info(_) ->           ?nif_stub.
config_locked(_) ->         ?nif_stub.
data_locked(_) ->           ?nif_stub.
slot_locked(_,_) ->         ?nif_stub.
serial_number(_) ->         ?nif_stub.
read_config(_) ->           ?nif_stub.
write_config(_) ->          ?nif_stub.
lock_config(_) ->           ?nif_stub.
lock_data(_) ->             ?nif_stub.
lock_slot(_,_) ->           ?nif_stub.
gen_private_key(_,_) ->     ?nif_stub.
gen_public_key(_,_) ->      ?nif_stub.
sign(_,_,_) ->              ?nif_stub.
verify_extern(_,_,_,_) ->   ?nif_stub.
verify_stored(_,_,_,_) ->   ?nif_stub.
write_comp_cert(_,_,_) ->   ?nif_stub.
read_comp_cert(_,_) ->      ?nif_stub.
gen_random_bytes(_) ->      ?nif_stub.
