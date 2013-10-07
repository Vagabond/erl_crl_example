
-module(server).

-export([start/0]).

start() ->
    application:ensure_all_started(ssl),
    {ok, LSock} = ssl:listen(5555, [{reuseaddr, true},
                                    {certfile, "CA/localhost/cert.pem"},
                                    {keyfile, "CA/localhost/key.pem"},
                                    {cacertfile, "CA/localhost/cacerts.pem"}]),
    {ok, NSock} = ssl:transport_accept(LSock),
    ok = ssl:ssl_accept(NSock),
    io:format("server accepted connection"),
    ssl:send(NSock, "0123456789"),
    ssl:close(NSock),
    ssl:close(LSock),
    ok.
