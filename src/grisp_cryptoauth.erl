-module(grisp_cryptoauth).

-export([device_info/0,
         config_locked/0,
         data_locked/0,
         serial_number/0,
         read_config/0]).

-on_load(init/0).

-define(APPNAME, grisp_cryptoauth).
-define(nif_stub, nif_stub_error(?LINE)).


device_info() ->    ?nif_stub.
config_locked() ->  ?nif_stub.
data_locked() ->    ?nif_stub.
serial_number() ->  ?nif_stub.
read_config() ->    ?nif_stub.

init() ->
    SoName = case code:priv_dir(?APPNAME) of
        {error, bad_name} ->
            case filelib:is_dir(filename:join(["..", priv])) of
                true ->
                    filename:join(["..", priv, ?APPNAME]);
                _ ->
                    filename:join([priv, ?APPNAME])
            end;
        Dir ->
            filename:join(Dir, ?APPNAME)
    end,
    erlang:load_nif(SoName, 0).

nif_stub_error(Line) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, Line}).
