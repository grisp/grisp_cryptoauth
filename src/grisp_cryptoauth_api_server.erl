-module(grisp_cryptoauth_api_server).

-behaviour(gen_server).

-export([start_link/0]).

-export([init/1,
         handle_call/3,
         handle_cast/2]).


-define(SLEEP_TIME_SEC, 5).


start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).


init(_Args) ->
    {ok, Context} = grisp_cryptoauth:init(),
    State = {Context, undefined},
    {ok, State}.


handle_call({Fun, Args}, _From, {Context, OldTRef}) ->
    %% on every API call reset a timer to put the device
    %% to sleep after SLEEP_TIME_SEC seconds to save energy
    timer:cancel(OldTRef), %% this doesn't throw on bad args
    {ok, NewTRef} = timer:apply_after(?SLEEP_TIME_SEC * 1000, grisp_cryptoauth, sleep, [Context]),
    try apply(grisp_cryptoauth, Fun, [Context | Args]) of
        Result -> {reply, {ok, Result}, {Context, NewTRef}}
    catch
        C:R:S -> {reply, {error, C, R, S}, {Context, NewTRef}}
    end.

handle_cast(_, State) ->
    {noreply, State}.
