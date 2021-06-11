-module(grisp_cryptoauth).

%% Main API
-export([sign/2]).

-define(PRIMARY_PRIVATE_KEY, 0).
-define(SECONDARY_PRIVATE_KEY_1, 2).
-define(SECONDARY_PRIVATE_KEY_2, 3).
-define(SECONDARY_PRIVATE_KEY_3, 4).


sign(primary, Msg) ->
    grisp_cryptoauth_basic:sign(?PRIMARY_PRIVATE_KEY, crypto:hash(sha256, Msg));
sign(secondary_1, Msg) ->
    grisp_cryptoauth_basic:sign(?SECONDARY_PRIVATE_KEY_1, crypto:hash(sha256, Msg));
sign(secondary_2, Msg) ->
    grisp_cryptoauth_basic:sign(?SECONDARY_PRIVATE_KEY_2, crypto:hash(sha256, Msg));
sign(secondary_3, Msg) ->
    grisp_cryptoauth_basic:sign(?SECONDARY_PRIVATE_KEY_3, crypto:hash(sha256, Msg)).
