
-module(server).

-export([start/0]).

start() ->
    application:ensure_all_started(ssl),
    {ok, LSock} = ssl:listen(5555, [{reuseaddr, true},
                                    {certfile, "CA/localhost/cert.pem"},
                                    {keyfile, "CA/localhost/key.pem"},
                                    {cacertfile, "CA/localhost/cacerts.pem"}]),
    {ok, LSock2} = ssl:listen(5556, [{reuseaddr, true},
                                    {certfile, "CA/server/cert.pem"},
                                    {keyfile, "CA/server/key.pem"},
                                    {cacertfile, "CA/server/cacerts.pem"}]),
    {ok, LSock3} = ssl:listen(5557, [{reuseaddr, true},
                                    {certfile, "CA/revoked/cert.pem"},
                                    {keyfile, "CA/revoked/key.pem"},
                                    {cacertfile, "CA/revoked/cacerts.pem"}]),

    accept(LSock),
    accept(LSock2),
    accept(LSock3),
    io:format("done~n").

accept(LSock) ->
    {ok, NSock} = ssl:transport_accept(LSock),
    case ssl:ssl_accept(NSock) of
        ok ->
            io:format("server accepted connection~n"),
            ssl:send(NSock, "0123456789"),
            ssl:close(NSock);
        Other ->
            io:format("connection failed ~p~n", [Other])
    end,
    ssl:close(LSock),
    ok.
