-module(grisp_cryptoauth_api_server).

-behaviour(gen_server).

-export([start_link/0]).

-export([init/1,
         handle_call/3,
         handle_cast/2]).


-define(RETRY_N, 10).
-define(RETRY_SLEEP, 1000).


start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).


init(_Args) ->
    {ok, Context} = grisp_cryptoauth:init(),
    case retry(grisp_cryptoauth_drv, serial_number, [], Context) of
        {ok, _} -> {ok, Context};
        Error   -> Error
    end.

handle_call({Fun, Args}, _From, Context) ->
    {reply, retry(grisp_cryptoauth, Fun, Args, Context), Context}.


handle_cast(_, State) ->
    {noreply, State}.


retry(Mod, Fun, Args, Context) ->
   retry(Mod, Fun, Args, Context, undefined, ?RETRY_N).

retry(_Mod, _Fun, _Args, _Context, Res, 0) ->
    Res;
retry(Mod, Fun, Args, Context, Res, N) ->
    timer:sleep(?RETRY_SLEEP),
    case apply(Mod, Fun, [Context | Args]) of
        {error, _} = Res    -> retry(Mod, Fun, Args, Context, Res, N-1);
        {error, _, _} = Res -> retry(Mod, Fun, Args, Context, Res, N-1);
        Result              -> Result
    end.
