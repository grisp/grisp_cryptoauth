-module(grisp_cryptoauth_api_server).

-behaviour(gen_server).

-export([start_link/0]).

-export([init/1,
         handle_call/3,
         handle_cast/2]).

-include_lib("kernel/include/logger.hrl").

-define(RETRY_N, 10).
-define(RETRY_SLEEP, 1000).


start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).


init(_Args) ->
    {ok, Context} = grisp_cryptoauth:init(),
    {ok, Context}.

handle_call({Fun, Args}, _From, Context) ->
    {reply, retry(grisp_cryptoauth, Fun, Args, Context), Context}.

handle_cast(_, State) ->
    {noreply, State}.


retry(Mod, Fun, Args, Context) ->
   retry(Mod, Fun, Args, Context, undefined, ?RETRY_N).

retry(_Mod, _Fun, _Args, _Context, Res, 0) ->
    Res;
retry(Mod, Fun, Args, Context, _, N) ->
    case apply(Mod, Fun, [Context | Args]) of
        {error, _} = Res ->
            ?LOG_WARNING(#{event => cryptoauthlib, status => error, function => Fun, attempt => (11-N), result => Res}),
            timer:sleep(?RETRY_SLEEP),
            retry(Mod, Fun, Args, Context, Res, N-1);
        {error, _, _} = Res ->
            ?LOG_WARNING(#{event => cryptoauthlib, status => error, function => Fun, attempt => (11-N), result => Res}),
            timer:sleep(?RETRY_SLEEP),
            retry(Mod, Fun, Args, Context, Res, N-1);
        Result ->
            ?LOG_DEBUG(#{event => cryptoauthlib, status => success, function => Fun, attempt => (11-N)}),
            Result
    end.
