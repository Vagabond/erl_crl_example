-module(client).

-include_lib("public_key/include/public_key.hrl").

-export([start/0]).

start() ->
    application:ensure_all_started(ssl),
    %% testing a certificate that is signed by a root CA
    {ok, Sock1} = ssl:connect("127.0.0.1", 5555, [{cacertfile, "CA/revoked/cacerts.pem"},
                                                 {reuse_sessions, false},
                                                 {verify, verify_peer},
                                                 {active, false},
                                                 {verify_fun, {fun validate_function/3, []}}]),
    {ok, "0123456789"} = ssl:recv(Sock1, 10),
    ssl:close(Sock1),

    %% testing a certificate signed by an intermediate CA
    {ok, Sock2} = ssl:connect("127.0.0.1", 5556, [{cacertfile, "CA/revoked/cacerts.pem"},
                                                 {reuse_sessions, false},
                                                 {verify, verify_peer},
                                                 {active, false},
                                                 {verify_fun, {fun validate_function/3, []}}]),
    {ok, "0123456789"} = ssl:recv(Sock2, 10),
    ssl:close(Sock2),

    %% testing an revoked certificate signed by an intermediate CA
    {error, _} = ssl:connect("127.0.0.1", 5557, [{cacertfile, "CA/revoked/cacerts.pem"},
                                                 {reuse_sessions, false},
                                                 {verify, verify_peer},
                                                 {active, false},
                                                 {verify_fun, {fun validate_function/3, []}}]),

    io:format("~nTEST PASSED~n"),

    ok.


validate_function(Cert, valid_peer, State) ->
    %% peer certificate validated, now check the CRL

    %% pull the CRL distribution point(s) out of the certificate, if any
    case pubkey_cert:select_extension(?'id-ce-cRLDistributionPoints',
                                      pubkey_cert:extensions_list(Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.extensions)) of
        undefined ->
            %% fail; we can't validate if there's no CRL
            {no_crl, State};
        CRLExtension ->
            CRLDistPoints = CRLExtension#'Extension'.extnValue,
            DPointsAndCRLs = lists:foldl(fun(Point, Acc) ->
                                                 %% try to read the CRL over http or from a local file
                                                 case fetch_point(Point) of
                                                     not_available ->
                                                         Acc;
                                                     Res ->
                                                         [{Point, Res} | Acc]
                                                 end
                                         end, [], CRLDistPoints),
            Res = (catch public_key:pkix_crls_validate(Cert, DPointsAndCRLs, [{issuer_fun, {fun issuer_function/4, "CA/revoked/cacerts.pem"}}])),
            io:format("crl validate result ~p~n", [Res]),
            {Res, State}
    end;
validate_function(_Cert, _Event, State) ->
    {valid, State}.

issuer_function(_DP, CRL, {_, _Issuer}, CACerts) ->
    %% XXX the 'Issuer' we get passed here is actually a lie, public key treats the Authority Key Identifier as the 'issuer'
    %% Read the CA certs out of the file
    {ok, Bin} = file:read_file(CACerts),
    Certs = [{DER, public_key:pkix_decode_cert(DER, otp)} || {'Certificate', DER, not_encrypted} <- public_key:pem_decode(Bin)],
    %% get the real issuer out of the CRL
    Issuer = public_key:pkix_normalize_name(pubkey_cert_records:transform(CRL#'CertificateList'.tbsCertList#'TBSCertList'.issuer, decode)),
    %% assume certificates are ordered from root to tip
    Match = lists:foldl(
              fun({DER, OTPCert}, undefined) ->
                      %% check if this certificate matches the issuer
                      Normal = public_key:pkix_normalize_name(OTPCert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject),
                      case Normal == Issuer of
                          true ->
                              build_chain({DER, OTPCert}, Certs, []);
                          false ->
                              undefined
                      end;
                 (_E, Acc) ->
                      %% already found a match
                      Acc
              end, undefined, Certs),
    case Match of
        undefined ->
            error;
        {OTPCert, Path} ->
            {ok, OTPCert, Path}
    end.

%% construct the chain of trust back to the root CA and return a tuple of
%% {RootCA :: #OTPCertificate{}, Chain :: [der_encoded()]}
build_chain({DER, Cert}, Certs, Acc) ->
    %% check if this cert is self-signed, if it is, we've reached the root of the chain
    Issuer = public_key:pkix_normalize_name(Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.issuer),
    Subject = public_key:pkix_normalize_name(Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject),
    case Issuer == Subject of
        true ->
            {Cert, [DER|Acc]};
        false ->
            Match = lists:foldl(
              fun({D, C}, undefined) ->
                      S = public_key:pkix_normalize_name(C#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject),
                      %% compare the subject to the current issuer
                      case Issuer == S of
                          true ->
                              %% we've found our man
                              {D, C};
                          false ->
                              undefined
                      end;
                 (_E, A) ->
                      %% already matched
                      A
              end, undefined, Certs),
            case Match of
                undefined ->
                    %% can't find the current cert's issuer
                    undefined;
                Match ->
                    build_chain(Match, Certs, [DER|Acc])
            end
    end.

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
            [{'CertificateList', DER, _}=CertList] = public_key:pem_decode(Bin),
            {DER, public_key:pem_entry_decode(CertList)};
        _ ->
            fetch(Rest)
    catch
        _:_ ->
            fetch(Rest)
    end;
fetch([{uniformResourceIdentifier, "http"++_=URL}|Rest]) ->
    inets:start(),
    case httpc:request(get, {URL, []}, [], [{body_format, binary}]) of
        {ok, _Status, _Headers, Body} ->
            [{'CertificateList', DER, _}=CertList] = public_key:pem_decode(Body),
            {DER, public_key:pem_entry_decode(CertList)};
        {error, _Reason} ->
            fetch(Rest)
    end.

