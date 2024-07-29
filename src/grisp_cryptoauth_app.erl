-module(grisp_cryptoauth_app).

-behaviour(application).

-export([start/2, stop/1]).


start(_StartType, _StartArgs) ->
    grisp_cryptoauth_sup:start_link().

stop(_State) ->
    ok.
