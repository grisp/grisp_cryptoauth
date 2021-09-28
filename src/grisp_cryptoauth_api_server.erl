-module(grisp_cryptoauth_api_server).

-behaviour(gen_server).

-export([start_link/0]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2]).


start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).


init(_Args) ->
    grisp_cryptoauth:init().


handle_call({Fun, Args}, _From, Context) ->
    {reply, apply(grisp_cryptoauth, Fun, [Context | Args]), Context}.


handle_cast(_, Context) ->
    {noreply, Context}.


handle_info(_, Context) ->
    {noreply, Context}.
