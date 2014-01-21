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
    init:stop().

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

%% @doc Validator function for SSL negotiation.
%%
validate_function(Cert, valid_peer, State) ->
    io:format("validing peer ~p with ~p intermediate certs~n",
                [get_common_name(Cert), 
                 length(element(2, State))]),
    %% peer certificate validated, now check the CRL
    Res = (catch check_crl(Cert, State)),
    io:format("CRL validate result for ~p: ~p~n",
                [get_common_name(Cert), Res]),
    {Res, State};
validate_function(Cert, valid, {TrustedCAs, IntermediateCerts}=State) ->
    case public_key:pkix_is_self_signed(Cert) of
        true ->
            io:format("root certificate~n"),
            %% this is a root cert, no CRL
            {valid, {TrustedCAs, [Cert|IntermediateCerts]}};
        false ->
            %% check is valid CA certificate, add to the list of
            %% intermediates
            Res = (catch check_crl(Cert, State)),
            io:format("CRL intermediate CA validate result for ~p: ~p~n",
                        [get_common_name(Cert), Res]),
            {Res, {TrustedCAs, [Cert|IntermediateCerts]}}
    end;
validate_function(_Cert, _Event, State) ->
    %io:format("ignoring event ~p~n", [_Event]),
    {valid, State}.

%% @doc Given a certificate, find CRL distribution points for the given
%%      certificate, fetch, and attempt to validate each CRL through
%%      issuer_function/4.
%%
check_crl(Cert, State) ->
    %% pull the CRL distribution point(s) out of the certificate, if any
    case pubkey_cert:select_extension(?'id-ce-cRLDistributionPoints',
                                      pubkey_cert:extensions_list(Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.extensions)) of
        undefined ->
            io:format("no CRL distribution points for ~p~n",
                         [get_common_name(Cert)]),
            %% fail; we can't validate if there's no CRL
            no_crl;
        CRLExtension ->
            CRLDistPoints = CRLExtension#'Extension'.extnValue,
            DPointsAndCRLs = lists:foldl(fun(Point, Acc) -> 
                            %% try to read the CRL over http or from a
                            %% local file
                            case fetch_point(Point) of
                                not_available ->
                                    Acc;
                                Res ->
                                    [{Point, Res} | Acc]
                            end 
                    end, [], CRLDistPoints),
            public_key:pkix_crls_validate(Cert, 
                                          DPointsAndCRLs, 
                                          [{issuer_fun, 
                                            {fun issuer_function/4, State}}])
    end.

%% @doc Given a list of distribution points for CRLs, certificates and
%%      both trusted and intermediary certificates, attempt to build and
%%      authority chain back via build_chain to verify that it is valid.
%%
issuer_function(_DP, CRL, _Issuer, {TrustedCAs, IntermediateCerts}) ->
    %% XXX the 'Issuer' we get passed here is the AuthorityKeyIdentifier,
    %% which we are not currently smart enough to understand
    %% Read the CA certs out of the file
    Certs = [public_key:pkix_decode_cert(DER, otp) || DER <- TrustedCAs],
    %% get the real issuer out of the CRL
    Issuer = public_key:pkix_normalize_name(
            pubkey_cert_records:transform(
                CRL#'CertificateList'.tbsCertList#'TBSCertList'.issuer, decode)),
    %% assume certificates are ordered from root to tip
    case find_issuer(Issuer, IntermediateCerts ++ Certs) of
        undefined ->
            io:format("unable to find certificate matching CRL issuer ~p~n", 
                        [Issuer]),
            error;
        IssuerCert ->
            case build_chain({public_key:pkix_encode('OTPCertificate', 
                                                     IssuerCert, 
                                                     otp), 
                              IssuerCert}, IntermediateCerts, Certs, []) of
                undefined ->
                    error;
                {OTPCert, Path} ->
                    {ok, OTPCert, Path}
            end
    end.

%% @doc Attempt to build authority chain back using intermediary
%%      certificates, falling back on trusted certificates if the
%%      intermediary chain of certificates does not fully extend to the 
%%      root.
%% 
%%      Returns: {RootCA :: #OTPCertificate{}, Chain :: [der_encoded()]}
%%
build_chain({DER, Cert}, IntCerts, TrustedCerts, Acc) ->
    %% check if this cert is self-signed, if it is, we've reached the
    %% root of the chain
    Issuer = public_key:pkix_normalize_name(
            Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.issuer),
    Subject = public_key:pkix_normalize_name(
            Cert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject),
    case Issuer == Subject of
        true ->
            case find_issuer(Issuer, TrustedCerts) of
                undefined ->
                    io:format("self-signed certificate is NOT trusted~n"),
                    undefined;
                TrustedCert ->
                    %% return the cert from the trusted list, to prevent
                    %% issuer spoofing
                    {TrustedCert, 
                     [public_key:pkix_encode(
                                'OTPCertificate', TrustedCert, otp)|Acc]}
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
                    io:format("Ran out of intermediate certs, switching to trusted certs~n"),
                    build_chain({DER, Cert}, TrustedCerts, TrustedCerts, Acc);
                undefined ->
                    io:format("Can't construct chain of trust beyond ~p~n",
                                [get_common_name(Cert)]),
                    %% can't find the current cert's issuer
                    undefined;
                Match ->
                    build_chain(Match, IntCerts, TrustedCerts, [DER|Acc])
            end
    end.

%% @doc Given a certificate and a list of trusted or intermediary
%%      certificates, attempt to find a match in the list or bail with
%%      undefined.
find_issuer(Issuer, Certs) ->
    lists:foldl(
      fun(OTPCert, undefined) ->
              %% check if this certificate matches the issuer
              Normal = public_key:pkix_normalize_name(
                        OTPCert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject),
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

%% @doc Find distribution points for a given CRL and then attempt to
%%      fetch the CRL from the first available.
fetch_point(#'DistributionPoint'{distributionPoint={fullName, Names}}) ->
    Decoded = [{NameType, 
                pubkey_cert_records:transform(Name, decode)} 
               || {NameType, Name} <- Names],
    fetch(Decoded).

%% @doc Given a list of locations to retrieve a CRL from, attempt to
%%      retrieve either from a file or http resource and bail as soon as
%%      it can be found.
%%
%%      Currently, only hand a armored PEM or DER encoded file, with
%%      defaulting to DER.
%%
fetch([]) ->
    not_available;
fetch([{uniformResourceIdentifier, "file://"++File}|Rest]) ->
    io:format("getting CRL from ~p~n", [File]),
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
    _ = inets:start(),
    case httpc:request(get, {URL, []}, [], [{body_format, binary}]) of
        {ok, {_Status, _Headers, Body}} ->
            case Body of
                <<"-----BEGIN", _/binary>> ->
                    [{'CertificateList', 
                      DER, _}=CertList] = public_key:pem_decode(Body),
                    {DER, public_key:pem_entry_decode(CertList)};
                _ ->
                    %% assume DER encoded
                    CertList = public_key:pem_entry_decode(
                            {'CertificateList', Body, not_encrypted}),
                    {Body, CertList}
            end;
        {error, _Reason} ->
            io:format("failed to get CRL ~p~n", [_Reason]),
            fetch(Rest)
    end;
fetch([Loc|Rest]) ->
    %% unsupported CRL location
    io:format("unable to fetch CRL from unsupported location ~p~n", 
                [Loc]),
    fetch(Rest).

%% get the common name attribute out of an OTPCertificate record
get_common_name(OTPCert) ->
    %% You'd think there'd be an easier way than this giant mess, but I
    %% couldn't find one.
    {rdnSequence, Subject} = OTPCert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject,
    case [Attribute#'AttributeTypeAndValue'.value || [Attribute] <- Subject,
        Attribute#'AttributeTypeAndValue'.type == ?'id-at-commonName'] of
        [Att] ->
            case Att of
                {teletexString, Str} -> Str;
                {printableString, Str} -> Str;
                {utf8String, Bin} -> binary_to_list(Bin)
            end;
        _ ->
            unknown
    end.
