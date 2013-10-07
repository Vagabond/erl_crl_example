-module(client).

-include_lib("public_key/include/public_key.hrl").

-export([start/0]).

start() ->
    application:ensure_all_started(ssl),
    Fun = fun(Cert, valid_peer, State) ->
                  io:format("got ~p, ~p, ~p~n", [Cert, valid_peer, State]),
                  case pubkey_cert:select_extension(?'id-ce-cRLDistributionPoints', pubkey_cert:extensions_list(Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.extensions)) of
                      undefined ->
                          {valid, State};
                      CRLExtension ->
                          CRLDistPoints = CRLExtension#'Extension'.extnValue,
                          io:format("CRL dist points ~p~n", [CRLDistPoints]),
                          Blah = lists:foldl(fun(Point, Acc) ->
                                                     case fetch_point(Point) of
                                                         not_available ->
                                                             Acc;
                                                         Res ->
                                                             [{Point, Res} | Acc]
                                                     end
                                             end, [], CRLDistPoints),
                          io:format("blah ~p~n", [Blah]),
                          Res = (catch public_key:pkix_crls_validate(Cert, Blah, [{issuer_fun, )),
                          io:format("crl validate result ~p~n", [Res]),
                          Res
                  end;
             (_Cert, _Event, State) ->
                  {valid, State}
          end,
    {ok, Sock} = ssl:connect("127.0.0.1", 5555, [{cacertfile, "CA/localhost/cacerts.pem"},
                                                 {reuse_sessions, false},
                                                 {verify, verify_peer},
                                                 {active, false},
                                                 {verify_fun, {Fun, []}}]),
    {ok, "0123456789"} = ssl:recv(Sock, 10),
    ssl:close(Sock),
    ok.

fetch_point(#'DistributionPoint'{distributionPoint = P}) ->
    case P of
        {fullName, Names} ->
            Decoded = [{NameType, pubkey_cert_records:transform(Name, decode)} || {NameType, Name} <- Names],
            fetch(Decoded)
    end.

fetch([]) ->
    not_available;
fetch([{uniformResourceIdentifier, "file://"++File}|Rest]) ->
    try file:read_file(File) of
        {ok, Bin} ->
            %% assume PEM
            [{'CertificateList', _, _}=CertList] = public_key:pem_decode(Bin),
            [CertList] = public_key:pem_decode(Bin),
            {wtf, public_key:pem_entry_decode(CertList)}
    catch
        _:_ ->
            fetch(Rest)
    end;
fetch([{uniformResourceIdentifier, "http"++_=URL}|Rest]) ->
    inets:start(),
    case httpc:request(get, {URL, []}, [], [{body_format, binary}]) of
        {ok, _Status, _Headers, Body} ->
            [{'CertificateList', _, _}=CertList] = public_key:pem_decode(Body),
            {wtf, public_key:pem_entry_decode(CertList)};
        {error, _Reason} ->
            fetch(Rest)
    end.

