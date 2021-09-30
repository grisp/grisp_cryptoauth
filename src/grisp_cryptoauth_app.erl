-module(grisp_cryptoauth_app).

-behaviour(application).

-export([start/2, stop/1]).


start(_StartType, _StartArgs) ->
    %% Only successful for GRiSP2 builds,
    %% meant to setup I2C bus through the
    %% GRiSP platform, otherwise the
    %% standard Linux bus driver is used.
    application:ensure_all_started(grisp),
    grisp:add_device(i2c, grisp_eeprom),
    grisp_cryptoauth_sup:start_link().


stop(_State) ->
    ok.
