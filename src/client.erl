-module(client).

-include_lib("public_key/include/public_key.hrl").

-export([start/0, start/1]).

start() ->
    application:ensure_all_started(ssl),
    io:format("wtf0~n"),
    CACerts = load_cert("CA/revoked/cacerts.pem"),
    %% testing a certificate that is signed by a root CA
    {ok, Sock1} = ssl:connect("127.0.0.1", 5555, [{cacerts, CACerts},
                                                 {reuse_sessions, false},
                                                 {verify, verify_peer},
                                                 {active, false},
                                                 {verify_fun, {fun validate_function/3, {CACerts, []}}}]),
    {ok, "0123456789"} = ssl:recv(Sock1, 10),
    ssl:close(Sock1),

    %% testing a certificate signed by an intermediate CA
    {ok, Sock2} = ssl:connect("127.0.0.1", 5556, [{cacerts, CACerts},
                                                 {reuse_sessions, false},
                                                 {verify, verify_peer},
                                                 {active, false},
                                                 {verify_fun, {fun validate_function/3, {CACerts, []}}}]),
    {ok, "0123456789"} = ssl:recv(Sock2, 10),
    ssl:close(Sock2),

    %% testing an revoked certificate signed by an intermediate CA
    {error, _} = ssl:connect("127.0.0.1", 5557, [{cacerts, CACerts},
                                                 {reuse_sessions, false},
                                                 {verify, verify_peer},
                                                 {active, false},
                                                 {verify_fun, {fun validate_function/3, {CACerts, []}}}]),

    io:format("~nTEST PASSED~n"),

    ok.

start([Host, Port]) ->
    application:ensure_all_started(ssl),
    CACerts = load_certs("/etc/ssl/certs"),
    %CACerts = load_certs("/home/andrew/lavabit"),
    %CACerts = load_certs("/home/andrew/lavabit"),
    {ok, Sock2} = ssl:connect(Host, list_to_integer(Port), [{cacerts, CACerts},
                                                 {reuse_sessions, false},
                                                 {depth, 9},
                                                 {verify, verify_peer},
                                                 {active, false},
                                                 {verify_fun, {fun validate_function/3, {CACerts, []}}}]),
    ok.

load_certs(undefined) ->
    undefined;
load_certs(CertDir) ->
    case file:list_dir(CertDir) of
        {ok, Certs} ->
            load_certs(lists:map(fun(Cert) -> filename:join(CertDir, Cert)
                    end, Certs), []);
        {error, _} ->
            undefined
    end.

load_certs([], Acc) ->
    io:format("Successfully loaded ~p CA certificates~n", [length(Acc)]),
    Acc;
load_certs([Cert|Certs], Acc) ->
    case filelib:is_dir(Cert) of
        true ->
            load_certs(Certs, Acc);
        _ ->
            %io:format("Loading certificate ~p~n", [Cert]),
            load_certs(Certs, load_cert(Cert) ++ Acc)
    end.

load_cert(Cert) ->
    {ok, Bin} = file:read_file(Cert),
    case filename:extension(Cert) of
        ".der" ->
            %% no decoding necessary
            [Bin];
        _ ->
            %% assume PEM otherwise
            Contents = public_key:pem_decode(Bin),
            [DER || {Type, DER, Cipher} <- Contents, Type == 'Certificate', Cipher == 'not_encrypted']
    end.

validate_function(Cert, valid_peer, State) ->
    %% peer certificate validated, now check the CRL

    %% pull the CRL distribution point(s) out of the certificate, if any
    case pubkey_cert:select_extension(?'id-ce-cRLDistributionPoints',
                                      pubkey_cert:extensions_list(Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.extensions)) of
        undefined ->
            io:format("no CRL distribution points~n"),
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
            Res = (catch public_key:pkix_crls_validate(Cert, DPointsAndCRLs, [{issuer_fun, {fun issuer_function/4, State}}])),
            io:format("crl validate result ~p~n", [Res]),
            {Res, State}
    end;
validate_function(Cert, valid, {TrustedCAs, IntermediateCerts}) ->
    %% valid CA certificate, add to the list of intermediates
    {valid, {TrustedCAs, [Cert|IntermediateCerts]}};
validate_function(_Cert, _Event, State) ->
    {valid, State}.

issuer_function(_DP, CRL, {_, _Issuer}, {TrustedCAs, IntermediateCerts}) ->
    %% XXX the 'Issuer' we get passed here is actually a lie, public key treats the Authority Key Identifier as the 'issuer'
    %% Read the CA certs out of the file
    %{ok, Bin} = file:read_file(CACerts),
    %CACerts = load_certs("/home/andrew/lavabit"),
    Certs = [public_key:pkix_decode_cert(DER, otp) || DER <- TrustedCAs],
    %% get the real issuer out of the CRL
    Issuer = public_key:pkix_normalize_name(pubkey_cert_records:transform(CRL#'CertificateList'.tbsCertList#'TBSCertList'.issuer, decode)),
    %% assume certificates are ordered from root to tip
    Match = lists:foldl(
              fun(OTPCert, undefined) ->
                      %% check if this certificate matches the issuer
                      Normal = public_key:pkix_normalize_name(OTPCert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject),
                      case Normal == Issuer of
                          true ->
                              build_chain({public_key:pkix_encode('OTPCertificate', OTPCert, otp), OTPCert}, IntermediateCerts, Certs, []);
                          false ->
                              undefined
                      end;
                 (_E, Acc) ->
                      %% already found a match
                      Acc
              end, undefined, IntermediateCerts),
    case Match of
        undefined ->
            io:format("unable to find certificate matching issuer ~p", [Issuer]),
            error;
        {OTPCert, Path} ->
            {ok, OTPCert, Path}
    end.

%% construct the chain of trust back to the root CA and return a tuple of
%% {RootCA :: #OTPCertificate{}, Chain :: [der_encoded()]}
build_chain({DER, Cert}, IntCerts, TrustedCerts, Acc) ->
    %% check if this cert is self-signed, if it is, we've reached the root of the chain
    Issuer = public_key:pkix_normalize_name(Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.issuer),
    Subject = public_key:pkix_normalize_name(Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject),
    case Issuer == Subject of
        true ->
            case find_issuer(Issuer, TrustedCerts) of
                undefined ->
                    undefined;
                TrustedCert ->
                    %% return the cert from the trusted list, to prevent issuer spoofing
                    {TrustedCert, [public_key:pkix_encode('OTPCertificate', TrustedCert, otp)|Acc]}
            end;
        false ->
            Match = lists:foldl(
              fun(C, undefined) ->
                      S = public_key:pkix_normalize_name(C#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject),
                      %% compare the subject to the current issuer
                      case Issuer == S of
                          true ->
                              %% we've found our man
                              {public_key:pkix_encode('OTPCertificate', C, otp), C};
                          false ->
                              undefined
                      end;
                 (_E, A) ->
                      %% already matched
                      A
              end, undefined, IntCerts),
            case Match of
                undefined when IntCerts /= TrustedCerts ->
                    %% continue the chain by using the trusted CAs
                    io:format("ran out of intermediate certs, switching to trusted certs~n"),
                    build_chain({DER, Cert}, TrustedCerts, TrustedCerts, Acc);
                undefined ->
                    io:format("can't construct chain~n"),
                    %% can't find the current cert's issuer
                    undefined;
                Match ->
                    build_chain(Match, IntCerts, TrustedCerts, [DER|Acc])
            end
    end.

find_issuer(Issuer, Certs) ->
    lists:foldl(
      fun(OTPCert, undefined) ->
              %% check if this certificate matches the issuer
              Normal = public_key:pkix_normalize_name(OTPCert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject),
              case Normal == Issuer of
                  true ->
                      OTPCert;
                  false ->
                      undefined
              end;
         (_E, Acc) ->
              %% already found a match
              Acc
      end, undefined, Certs).

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
    io:format("getting CRL from ~p~n", [URL]),
    inets:start(),
    case httpc:request(get, {URL, []}, [], [{body_format, binary}]) of
        {ok, {_Status, _Headers, Body}} ->
            case Body of
                <<"-----BEGIN", _/binary>> ->
                    [{'CertificateList', DER, _}=CertList] = public_key:pem_decode(Body),
                    {DER, public_key:pem_entry_decode(CertList)};
                _ ->
                    %% assume DER encoded
                    CertList = public_key:pem_entry_decode({'CertificateList', Body, not_encrypted}),
                    {Body, CertList}
            end;
        {error, _Reason} ->
            io:format("failed to get CRL ~p~n", [_Reason]),
            fetch(Rest)
    end.

