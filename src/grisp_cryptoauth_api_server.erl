-module(grisp_cryptoauth_api_server).

-behaviour(gen_server).

-include_lib("kernel/include/logger.hrl").

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
    {reply, retry(5, 300, Fun, [Context | Args]), {Context, NewTRef}}.

handle_cast(_, State) ->
    {noreply, State}.

retry(RetryCount, SleepTime, Fun, Args) ->
    try apply(grisp_cryptoauth, Fun, Args) of
        {error, _} = Error when RetryCount =< 1 ->
            Error;
        {error, _} = Error ->
            ?LOG_WARNING("Error while calling function ~w [~w] ~p",
                         [Fun, RetryCount - 1, Error]),
            timer:sleep(SleepTime),
            retry(RetryCount - 1, SleepTime, Fun, Args);
        Result ->
            {ok, Result}
    catch
        C:R:S when RetryCount =< 1 ->
            {error, C, R, S};
        Class:Reason ->
            ?LOG_WARNING("Exception while calling function ~w [~w]: ~w:~p",
                         [Fun, RetryCount - 1, Class, Reason]),
            timer:sleep(SleepTime),
            retry(RetryCount - 1, SleepTime, Fun, Args)
    end.
