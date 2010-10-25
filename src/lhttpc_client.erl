%%% ----------------------------------------------------------------------------
%%% Copyright (c) 2009, Erlang Training and Consulting Ltd.
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions are met:
%%%    * Redistributions of source code must retain the above copyright
%%%      notice, this list of conditions and the following disclaimer.
%%%    * Redistributions in binary form must reproduce the above copyright
%%%      notice, this list of conditions and the following disclaimer in the
%%%      documentation and/or other materials provided with the distribution.
%%%    * Neither the name of Erlang Training and Consulting Ltd. nor the
%%%      names of its contributors may be used to endorse or promote products
%%%      derived from this software without specific prior written permission.
%%%
%%% THIS SOFTWARE IS PROVIDED BY Erlang Training and Consulting Ltd. ''AS IS''
%%% AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
%%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
%%% ARE DISCLAIMED. IN NO EVENT SHALL Erlang Training and Consulting Ltd. BE
%%% LIABLE SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
%%% BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
%%% WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
%%% OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
%%% ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%% ----------------------------------------------------------------------------

%%% @private
%%% @author Oscar Hellström <oscar@hellstrom.st>
%%% @doc
%%% This module implements the HTTP request handling. This should normally
%%% not be called directly since it should be spawned by the lhttpc module.
-module(lhttpc_client).

-export([request/9]).

-include("lhttpc_types.hrl").

-record(client_state, {
        host :: string(),
        port = 80 :: integer(),
        ssl = false :: true | false,
        method :: string(),
        request :: iolist(),
        request_headers :: headers(),
        socket,
        connect_timeout = infinity :: timeout(),
        connect_options = [] :: [any()],
        attempts :: integer(),
        requester :: pid(),
        partial_upload = false :: true | false,
        chunked_upload = false :: true | false,
        upload_window :: non_neg_integer() | infinity,
        partial_download = false :: true | false,
        download_window = infinity :: timeout(),
        part_size :: non_neg_integer() | infinity,
        %% in case of infinity we read whatever data we can get from
        %% the wire at that point or in case of chunked one chunk
        drop_response_body = false :: true | false,
        %% The following record members are all related to the stats
        %% measurements.
        measure_stats = false :: true | false,
        request_headers_len :: non_neg_integer(),
        decode_packet_type :: atom(),
        decode_packet_more :: binary(),
        timings_step :: atom(),
        timings_tick :: term()
    }).

-define(CONNECTION_HDR(HDRS, DEFAULT),
    string:to_lower(lhttpc_lib:header_value("connection", HDRS, DEFAULT))).

-define(DROP_BLOCK_SIZE, 4096).

-spec request(pid(), string(), 1..65535, true | false, string(),
        string() | atom(), headers(), iolist(), [option()]) -> no_return().
%% @spec (From, Host, Port, Ssl, Path, Method, Hdrs, RequestBody, Options) -> ok
%%    From = pid()
%%    Host = string()
%%    Port = integer()
%%    Ssl = boolean()
%%    Method = atom() | string()
%%    Hdrs = [Header]
%%    Header = {string() | atom(), string()}
%%    Body = iolist()
%%    Options = [Option]
%%    Option = {connect_timeout, Milliseconds}
%% @end
request(From, Host, Port, Ssl, Path, Method, Hdrs, Body, Options) ->
    % If the caller wants us to report timings, we start the clock now.
    % The clock will be stopped at the end of this function and the
    % timings will be sent to the target process just after.
    Measure_Stats = proplists:is_defined(report_stats, Options),
    {Stats_Pid, Stats_Data, Timings_Start} = if
        Measure_Stats ->
            {_, T_Pid, T_Data} = lists:keyfind(report_stats, 1, Options),
            {T_Pid, T_Data, erlang:now()};
        true ->
            {undefined, undefined, undefined}
    end,
    Result = try
        execute(From, Host, Port, Ssl, Path, Method, Hdrs, Body, Options,
          Measure_Stats, Timings_Start)
    catch
        Reason ->
            {response, self(), {error, Reason}};
        error:closed ->
            {response, self(), {error, connection_closed}};
        error:Error ->
            {exit, self(), {Error, erlang:get_stacktrace()}}
    end,
    % We can now stop the clock and send the stats, if the caller
    % requested it. Doing it here permits us to report stats even in
    % case of an error.
    if
        Measure_Stats ->
            % Stats are messages sent to this process (self()). We
            % receive them now.
            Stats = gather_stats([]),
            % The total time of the request is based on the
            % Timings_Start (taken at the beginning of this function)
            % and the last timing end.
            Timings_Stop = erlang:now(),
            Stats2 = [
              {total_time, {Timings_Start, Timings_Stop}}
              | Stats
            ],
            % We can now send those informations to the target process.
            Stats_Pid ! {lhttpc, stats, Stats2, Stats_Data};
        true ->
            ok
    end,
    case Result of
        {response, _, {ok, {no_return, _}}} -> ok;
        _Else                               -> From ! Result
    end,
    % Don't send back {'EXIT', self(), normal} if the process
    % calling us is trapping exits
    unlink(From),
    ok.

gather_stats(Stats) ->
    receive
        {stat, Type, Data} ->
            gather_stats([{Type, Data} | Stats])
    after 0 ->
            Stats
    end.

execute(From, Host, Port, Ssl, Path, Method, Hdrs, Body, Options,
  Measure_Stats, Timings_Start) ->
    UploadWindowSize = proplists:get_value(partial_upload, Options),
    PartialUpload = proplists:is_defined(partial_upload, Options),
    PartialDownload = proplists:is_defined(partial_download, Options),
    PartialDownloadOptions = proplists:get_value(partial_download, Options, []),
    NormalizedMethod = lhttpc_lib:normalize_method(Method),
    {ChunkedUpload, Request, Headers_Len} = lhttpc_lib:format_request(Path,
      NormalizedMethod, Hdrs, Host, Port, Body, PartialUpload, Measure_Stats),
    SocketRequest = {socket, self(), Host, Port, Ssl},
    Socket = case gen_server:call(lhttpc_manager, SocketRequest, infinity) of
        {ok, S}   -> S; % Re-using HTTP/1.1 connections
        no_socket -> undefined % Opening a new HTTP/1.1 connection
    end,
    State = #client_state{
        host = Host,
        port = Port,
        ssl = Ssl,
        method = NormalizedMethod,
        request = Request,
        requester = From,
        request_headers = Hdrs,
        socket = Socket,
        connect_timeout = proplists:get_value(connect_timeout, Options,
            infinity),
        connect_options = proplists:get_value(connect_options, Options, []),
        attempts = 1 + proplists:get_value(send_retry, Options, 1),
        partial_upload = PartialUpload,
        upload_window = UploadWindowSize,
        chunked_upload = ChunkedUpload,
        partial_download = PartialDownload,
        download_window = proplists:get_value(window_size,
            PartialDownloadOptions, infinity),
        part_size = proplists:get_value(part_size,
            PartialDownloadOptions, infinity),
        drop_response_body = proplists:get_bool(drop_response_body, Options),
        measure_stats = Measure_Stats,
        request_headers_len = Headers_Len,
        timings_tick = Timings_Start

    },
    Response = case send_request(State) of
        {R, undefined} ->
            {ok, R};
        {R, NewSocket} ->
            % The socket we ended up doing the request over is returned
            % here, it might be the same as Socket, but we don't know.
            % I've noticed that we don't want to give send sockets that we
            % can't change the controlling process for to the manager. This
            % really shouldn't fail, but it could do if:
            % * The socket was closed remotely already
            % * Due to an error in this module (returning dead sockets for
            %   instance)
            ManagerPid = whereis(lhttpc_manager),
            case lhttpc_sock:controlling_process(NewSocket, ManagerPid, Ssl) of
                ok ->
                    gen_server:cast(lhttpc_manager,
                        {done, Host, Port, Ssl, NewSocket});
                _ ->
                    ok
            end,
            {ok, R}
    end,
    {response, self(), Response}.

send_request(#client_state{attempts = 0}) ->
    % Don't try again if the number of allowed attempts is 0.
    throw(connection_closed);
send_request(#client_state{socket = undefined} = State) ->
    Host = State#client_state.host,
    Port = State#client_state.port,
    Ssl = State#client_state.ssl,
    Timeout = State#client_state.connect_timeout,
    ConnectOptions = State#client_state.connect_options,
    SocketOptions = [binary, {packet, http}, {active, false} | ConnectOptions],
    Measure_Stats = State#client_state.measure_stats,
    {NewState, Ret} = if
        Measure_Stats ->
            % Statistic: timing, "Resolve hostname" and "Open connection".
            % When measuring timings, we split the connection into
            % two steps:
            %   - name resolution
            %   - connection opening
            Step1  = dns_lookup_time,
            Start1 = State#client_state.timings_tick,
            Ret1   = lhttpc_sock:resolve_host(Host),
            Stop1  = erlang:now(),
            self() ! {stat, Step1, {Start1, Stop1}},
            State2 = State#client_state{
              timings_step = Step1,
              timings_tick = Stop1
            },
            case Ret1 of
                {ok, IP_Addr, Family} ->
                    Step2  = connection_time,
                    Start2 = Stop1,
                    % ssl (old implement) rejects inet or inet6 options...
                    SocketOptions2 = if
                        Ssl  -> [gather_stats | SocketOptions];
                        true -> [gather_stats, Family | SocketOptions]
                    end,
                    Ret2 = lhttpc_sock:connect(IP_Addr, Port,
                      SocketOptions2, Timeout, Ssl),
                    Stop2  = erlang:now(),
                    self() ! {stat, Step2, {Start2, Stop2}},
                    State3 = State2#client_state{
                      timings_step = Step2,
                      timings_tick = Stop2
                    },
                    {
                      State3,
                      Ret2
                    };
                {error, Reason2} ->
                    {
                      State2,
                      {error, Reason2}
                    }
            end;
        true ->
            {
              State,
              lhttpc_sock:connect(Host, Port, SocketOptions, Timeout, Ssl)
            }
    end,
    case Ret of
        {ok, Socket} ->
            send_request(NewState#client_state{socket = Socket});
        {error, etimedout} ->
            % TCP stack decided to give up
            throw(connect_timeout);
        {error, timeout} ->
            throw(connect_timeout);
        {error, Reason} ->
            erlang:error(Reason)
    end;
send_request(State) ->
    Socket = State#client_state.socket,
    Ssl = State#client_state.ssl,
    Request = State#client_state.request,
    lhttpc_sock:reset_stats(Socket),
    case lhttpc_sock:send(Socket, Request, Ssl) of
        ok ->
            if
                State#client_state.partial_upload -> partial_upload(State);
                true                              -> read_response(State)
            end;
        {error, closed} ->
            lhttpc_sock:close(Socket, Ssl),
            NewState = State#client_state{
                socket = undefined,
                attempts = State#client_state.attempts - 1
            },
            send_request(NewState);
        {error, Reason} ->
            lhttpc_sock:close(Socket, Ssl),
            erlang:error(Reason)
    end.

partial_upload(State) ->
    Response = {ok, {self(), State#client_state.upload_window}},
    State#client_state.requester ! {response, self(), Response},
    partial_upload_loop(State#client_state{attempts = 1, request = undefined}).

partial_upload_loop(State = #client_state{requester = Pid}) ->
    receive
        {trailers, Pid, Trailers} ->
            send_trailers(State, Trailers),
            read_response(State);
        {body_part, Pid, http_eob} ->
            NewState = send_body_part(State, http_eob),
            read_response(NewState);
        {body_part, Pid, Data} ->
            NewState = send_body_part(State, Data),
            Pid ! {ack, self()},
            partial_upload_loop(NewState)
    end.

send_body_part(State = #client_state{socket = Socket, ssl = Ssl}, BodyPart) ->
    Data = encode_body_part(State, BodyPart),
    check_send_result(State, lhttpc_sock:send(Socket, Data, Ssl)).

send_trailers(State = #client_state{chunked_upload = true}, Trailers) ->
    Socket = State#client_state.socket,
    Ssl = State#client_state.ssl,
    Data = [<<"0\r\n">>, lhttpc_lib:format_hdrs(Trailers)],
    check_send_result(State, lhttpc_sock:send(Socket, Data, Ssl));
send_trailers(#client_state{chunked_upload = false}, _Trailers) ->
    erlang:error(trailers_not_allowed).

encode_body_part(#client_state{chunked_upload = true}, http_eob) ->
    <<"0\r\n\r\n">>; % We don't send trailers after http_eob
encode_body_part(#client_state{chunked_upload = false}, http_eob) ->
    <<>>;
encode_body_part(#client_state{chunked_upload = true}, Data) ->
    Size = list_to_binary(erlang:integer_to_list(iolist_size(Data), 16)),
    [Size, <<"\r\n">>, Data, <<"\r\n">>];
encode_body_part(#client_state{chunked_upload = false}, Data) ->
    Data.

check_send_result(State, ok) ->
    State;
check_send_result(#client_state{socket = Sock, ssl = Ssl}, {error, Reason}) ->
    lhttpc_sock:close(Sock, Ssl),
    throw(Reason).

read_response(#client_state{socket = Socket, ssl = Ssl} = State) ->
    % Statistic: timing, "Send request".
    % Statistic: data sent, "Whole request".
    State2 = if
        State#client_state.measure_stats ->
            Step  = request_send_time,
            Start = State#client_state.timings_tick,
            Stop  = erlang:now(),
            self() ! {stat, Step, {Start, Stop}},
            Bytes_Sent = lhttpc_sock:get_stat(Socket, bytes_sent),
            Headers_Len = State#client_state.request_headers_len,
            Body_Len    = Bytes_Sent - Headers_Len,
            self() ! {stat, request_headers_length, Headers_Len},
            self() ! {stat, request_body_length,    Body_Len},
            self() ! {stat, request_length,         Bytes_Sent},
            ok = lhttpc_sock:setopts(Socket, [{packet, raw}], Ssl),
            State#client_state{
              decode_packet_type = http,
              decode_packet_more = <<>>,
              timings_step = Step,
              timings_tick = Stop
            };
        true ->
            lhttpc_sock:setopts(Socket, [{packet, http}], Ssl),
            State
    end,
    read_response(State2, nil, {nil, nil}, []).

read_response(State, Vsn, Status, Hdrs) ->
    Socket = State#client_state.socket,
    Ssl = State#client_state.ssl,
    Ret = lhttpc_sock:recv(Socket, Ssl),
    % Statistic: timing, "Wait response".
    State2 = if
        State#client_state.measure_stats andalso
        State#client_state.timings_step /= response_wait_time ->
            Step  = response_wait_time,
            Start = State#client_state.timings_tick,
            Stop  = erlang:now(),
            self() ! {stat, Step, {Start, Stop}},
            State#client_state{
              timings_step = Step,
              timings_tick = Stop
            };
        true ->
            State
    end,
    case Ret of
        {ok, Packet} ->
            if
                State2#client_state.measure_stats ->
                    Decode_Type = State2#client_state.decode_packet_type,
                    Decode_More = State2#client_state.decode_packet_more,
                    Packet2 = case Decode_More of
                        <<>> -> Packet;
                        _    -> list_to_binary([Decode_More, Packet])
                    end,
                    case erlang:decode_packet(Decode_Type, Packet2, []) of
                        {ok, HTTP_Packet, Rest} ->
                            State3 = State2#client_state{
                              decode_packet_more = <<>>
                            },
                            lhttpc_sock:unrecv(Socket, Rest),
                            read_response2(State3, Vsn, Status, Hdrs,
                              HTTP_Packet);
                        {more, _} ->
                            State3 = State2#client_state{
                              decode_packet_more = Packet2
                            },
                            read_response(State3, Vsn, Status, Hdrs);
                        {error, Reason} ->
                            erlang:error(Reason)
                    end;
                true ->
                    read_response2(State2, Vsn, Status, Hdrs, Packet)
            end;
        {error, closed} ->
            % Either we only noticed that the socket was closed after we
            % sent the request, the server closed it just after we put
            % the request on the wire or the server has some issues and is
            % closing connections without sending responses.
            % If this the first attempt to send the request, we will try again.
            lhttpc_sock:close(Socket, Ssl),
            NewState = State2#client_state{
                socket = undefined,
                attempts = State#client_state.attempts - 1
            },
            send_request(NewState);
        {error, Reason} ->
            erlang:error(Reason)
    end.

read_response2(State, Vsn, {StatusCode, _} = Status, Hdrs, HTTP_Packet) ->
    case HTTP_Packet of
        {http_response, NewVsn, NewStatusCode, Reason} ->
            NewStatus = {NewStatusCode, Reason},
            State2 = State#client_state{
              decode_packet_type = httph
            },
            read_response(State2, NewVsn, NewStatus, Hdrs);
        {http_header, _, Name, _, Value} ->
            Header = {lhttpc_lib:maybe_atom_to_list(Name), Value},
            read_response(State, Vsn, Status, [Header | Hdrs]);
        http_eoh when StatusCode >= 100, StatusCode =< 199 ->
            % RFC 2616, section 10.1:
            % A client MUST be prepared to accept one or more
            % 1xx status responses prior to a regular
            % response, even if the client does not expect a
            % 100 (Continue) status message. Unexpected 1xx
            % status responses MAY be ignored by a user agent.
            read_response(State, nil, {nil, nil}, []);
        http_eoh ->
            Socket = State#client_state.socket,
            Ssl = State#client_state.ssl,
            % Statistic: data received, "Response headers".
            Header_Len = if
                State#client_state.measure_stats ->
                    Socket = State#client_state.socket,
                    Bytes_Received1 = lhttpc_sock:get_stat(Socket,
                      bytes_received),
                    self() ! {stat, response_headers_length, Bytes_Received1},
                    Bytes_Received1;
                true ->
                    0
            end,
            ok = lhttpc_sock:setopts(Socket, [{packet, raw}], Ssl),
            {_, Response} = handle_response_body(State, Vsn, Status, Hdrs),
            % Statistic: data received, "Whole response".
            if
                State#client_state.measure_stats ->
                    Socket = State#client_state.socket,
                    Bytes_Received2 = lhttpc_sock:get_stat(Socket,
                      bytes_received),
                    Body_Len = Bytes_Received2 - Header_Len,
                    self() ! {stat, response_body_length, Body_Len},
                    self() ! {stat, response_length,      Bytes_Received2};
                true ->
                    ok
            end,
            NewHdrs = element(2, Response),
            ReqHdrs = State#client_state.request_headers,
            NewSocket = maybe_close_socket(Socket, Ssl, Vsn, ReqHdrs, NewHdrs),
            {Response, NewSocket};
        {http_error, Data} ->
            erlang:error({bad_header, Data})
    end.

handle_response_body(#client_state{partial_download = false} = State, Vsn,
        Status, Hdrs) ->
    Drop = State#client_state.drop_response_body,
    Socket = State#client_state.socket,
    Ssl = State#client_state.ssl,
    Method = State#client_state.method,
    {Body, NewHdrs, State2} = case has_body(Method, element(1, Status), Hdrs) of
        true ->
            read_body(Vsn, Hdrs, Ssl, Socket, body_type(Hdrs), Drop,
              State);
        false ->
            {<<>>, Hdrs, State}
    end,
    % Statistic: timing, "Receive response".
    State3 = if
        State2#client_state.measure_stats ->
            Step  = response_recv_time,
            Start = State2#client_state.timings_tick,
            Stop  = erlang:now(),
            self() ! {stat, Step, {Start, Stop}},
            State2#client_state{
              timings_step = Step,
              timings_tick = Stop
            };
        true ->
            State2
    end,
    {State3, {Status, NewHdrs, Body}};
handle_response_body(#client_state{partial_download = true} = State, Vsn,
        Status, Hdrs) ->
    Method = State#client_state.method,
    Ret = case has_body(Method, element(1, Status), Hdrs) of
        true ->
            Response = {ok, {Status, Hdrs, self()}},
            State#client_state.requester ! {response, self(), Response},
            MonRef = erlang:monitor(process, State#client_state.requester),
            Res = read_partial_body(State, Vsn, Hdrs, body_type(Hdrs)),
            erlang:demonitor(MonRef, [flush]),
            Res;
        false ->
            {Status, Hdrs, undefined}
    end,
    % Statistic: timing, "Receive response".
    State2 = if
        State#client_state.measure_stats ->
            Step  = response_recv_time,
            Start = State#client_state.timings_tick,
            Stop  = erlang:now(),
            self() ! {stat, Step, {Start, Stop}},
            State#client_state{
              timings_step = Step,
              timings_tick = Stop
            };
        true ->
            State
    end,
    {State2, Ret}.

has_body("HEAD", _, _) ->
    % HEAD responses aren't allowed to include a body
    false;
has_body("OPTIONS", _, Hdrs) ->
    % OPTIONS can include a body, if Content-Length or Transfer-Encoding
    % indicates it
    ContentLength = lhttpc_lib:header_value("content-length", Hdrs),
    TransferEncoding = lhttpc_lib:header_value("transfer-encoding", Hdrs),
    case {ContentLength, TransferEncoding} of
        {undefined, undefined} -> false;
        {_, _}                 -> true
    end;
has_body(_, 204, _) ->
    false; % RFC 2616 10.2.5: 204 No Content
has_body(_, 304, _) ->
    false; % RFC 2616 10.3.5: 304 Not Modified
has_body(_, _, _) ->
    true. % All other responses are assumed to have a body

body_type(Hdrs) ->
    % Find out how to read the entity body from the request.
    % * If we have a Content-Length, just use that and read the complete
    %   entity.
    % * If Transfer-Encoding is set to chunked, we should read one chunk at
    %   the time
    % * If neither of this is true, we need to read until the socket is
    %   closed (AFAIK, this was common in versions before 1.1).
    case lhttpc_lib:header_value("content-length", Hdrs) of
        undefined ->
            TransferEncoding = string:to_lower(
                lhttpc_lib:header_value("transfer-encoding", Hdrs, "undefined")
            ),
            case TransferEncoding of
                "chunked" -> chunked;
                _         -> infinite
            end;
        ContentLength ->
            {fixed_length, list_to_integer(ContentLength)}
    end.

read_partial_body(State, _Vsn, Hdrs, chunked) ->
    Window = State#client_state.download_window,
    read_partial_chunked_body(State, Hdrs, Window, 0, [], 0);
read_partial_body(State, Vsn, Hdrs, infinite) ->
    check_infinite_response(Vsn, Hdrs),
    read_partial_infinite_body(State, Hdrs, State#client_state.download_window);
read_partial_body(State, _Vsn, Hdrs, {fixed_length, ContentLength}) ->
    read_partial_finite_body(State, Hdrs, ContentLength,
        State#client_state.download_window).

read_body(_Vsn, Hdrs, Ssl, Socket, chunked, Drop, State) ->
    read_chunked_body(Socket, Ssl, Hdrs, [], Drop, State);
read_body(Vsn, Hdrs, Ssl, Socket, infinite, Drop, State) ->
    check_infinite_response(Vsn, Hdrs),
    {Body, Hdrs} = read_infinite_body(Socket, Hdrs, Ssl, Drop),
    {Body, Hdrs, State};
read_body(_Vsn, Hdrs, Ssl, Socket, {fixed_length, ContentLength}, Drop, State) ->
    {Body, Hdrs} = read_length(Hdrs, Ssl, Socket, ContentLength, Drop),
    {Body, Hdrs, State}.

read_partial_finite_body(State = #client_state{}, Hdrs, 0, _Window) ->
    reply_end_of_body(State, [], Hdrs);
read_partial_finite_body(State = #client_state{requester = To}, Hdrs,
        ContentLength, 0) ->
    receive
        {ack, To} ->
            read_partial_finite_body(State, Hdrs, ContentLength, 1);
        {'DOWN', _, process, To, _} ->
            exit(normal)
    end;
read_partial_finite_body(State, Hdrs, ContentLength, Window) when Window >= 0->
    Bin = read_body_part(State, ContentLength),
    State#client_state.requester ! {body_part, self(), Bin},
    To = State#client_state.requester,
    receive
        {ack, To} ->
            Length = ContentLength - iolist_size(Bin),
            read_partial_finite_body(State, Hdrs, Length, Window);
        {'DOWN', _, process, To, _} ->
            exit(normal)
    after 0 ->
            Length = ContentLength - iolist_size(Bin),
        read_partial_finite_body(State, Hdrs, Length, lhttpc_lib:dec(Window))
    end.

read_body_part(#client_state{part_size = infinity} = State, _ContentLength) ->
    case lhttpc_sock:recv(State#client_state.socket, State#client_state.ssl) of
        {ok, Data} ->
            Data;
        {error, Reason} ->
            erlang:error(Reason)
    end;
read_body_part(#client_state{part_size = PartSize} = State, ContentLength)
        when PartSize =< ContentLength ->
    Socket = State#client_state.socket, 
    Ssl = State#client_state.ssl,
    PartSize = State#client_state.part_size,
    case lhttpc_sock:recv(Socket, PartSize, Ssl) of
        {ok, Data} ->
            Data;
        {error, Reason} ->
            erlang:error(Reason)
    end;
read_body_part(#client_state{part_size = PartSize} = State, ContentLength)
        when PartSize > ContentLength ->
    Socket = State#client_state.socket, 
    Ssl = State#client_state.ssl,
    case lhttpc_sock:recv(Socket, ContentLength, Ssl) of
        {ok, Data} ->
            Data;
        {error, Reason} ->
            erlang:error(Reason)
    end.

read_length(Hdrs, Ssl, Socket, Length, false) ->
    case lhttpc_sock:recv(Socket, Length, Ssl) of
        {ok, Data} ->
            {Data, Hdrs};
        {error, Reason} ->
            erlang:error(Reason)
    end;
read_length(Hdrs, Ssl, Socket, Length, true) when Length > 0 ->
    % The caller isn't insterested in the body, but we must read it
    % from the socket anyway. We read by small chunk of data to avoid
    % increasing process memory footprint.
    ReadLength = if
        Length <  ?DROP_BLOCK_SIZE -> Length;
        Length >= ?DROP_BLOCK_SIZE -> ?DROP_BLOCK_SIZE
    end,
    case lhttpc_sock:recv(Socket, ReadLength, Ssl) of
        {ok, _} ->
            read_length(Hdrs, Ssl, Socket, Length - ReadLength, true);
        {error, Reason} ->
            erlang:error(Reason)
    end;
read_length(Hdrs, _, _, _, true) ->
    {<<>>, Hdrs}.

read_partial_chunked_body(State, Hdrs, Window, BufferSize, Buffer, 0) ->
    Socket = State#client_state.socket,
    Ssl = State#client_state.ssl,
    PartSize = State#client_state.part_size,
    case read_chunk_size(Socket, Ssl) of
        0 ->
            reply_chunked_part(State, Buffer, Window),
            {Trailers, NewHdrs, State2} = read_trailers(Socket, Ssl, [], Hdrs, State),
            reply_end_of_body(State2, Trailers, NewHdrs);
        ChunkSize when PartSize =:= infinity ->
            Chunk = read_chunk(Socket, Ssl, ChunkSize, false),
            NewWindow = reply_chunked_part(State, [Chunk | Buffer], Window),
            read_partial_chunked_body(State, Hdrs, NewWindow, 0, [], 0);
        ChunkSize when BufferSize + ChunkSize >= PartSize ->
            {Chunk, RemSize} = read_partial_chunk(Socket, Ssl,
                PartSize - BufferSize, ChunkSize),
            NewWindow = reply_chunked_part(State, [Chunk | Buffer], Window),
            read_partial_chunked_body(State, Hdrs, NewWindow, 0, [], RemSize);
        ChunkSize ->
            Chunk = read_chunk(Socket, Ssl, ChunkSize, false),
            read_partial_chunked_body(State, Hdrs, Window,
                BufferSize + ChunkSize, [Chunk | Buffer], 0)
    end;
read_partial_chunked_body(State, Hdrs, Window, BufferSize, Buffer, RemSize) ->
    Socket = State#client_state.socket,
    Ssl = State#client_state.ssl,
    PartSize = State#client_state.part_size,
    if
        BufferSize + RemSize >= PartSize ->
            {Chunk, NewRemSize} =
                read_partial_chunk(Socket, Ssl, PartSize - BufferSize, RemSize),
            NewWindow = reply_chunked_part(State, [Chunk | Buffer], Window),
            read_partial_chunked_body(State, Hdrs, NewWindow, 0, [],
                NewRemSize);
        BufferSize + RemSize < PartSize ->
            Chunk = read_chunk(Socket, Ssl, RemSize, false),
            read_partial_chunked_body(State, Hdrs, Window, BufferSize + RemSize,
                [Chunk | Buffer], 0)
    end.

read_chunk_size(Socket, Ssl) ->
    ok = lhttpc_sock:setopts(Socket, [{packet, line}], Ssl),
    case lhttpc_sock:recv(Socket, Ssl) of
        {ok, ChunkSizeExt} ->
            chunk_size(ChunkSizeExt);
        {error, Reason} ->
            erlang:error(Reason)
    end.

reply_chunked_part(_State, [], Window) ->
    Window;
reply_chunked_part(State = #client_state{requester = Pid}, Buff, 0) ->
    receive
        {ack, Pid} ->
            reply_chunked_part(State, Buff, 1);
        {'DOWN', _, process, Pid, _} ->
            exit(normal)
    end;
reply_chunked_part(#client_state{requester = Pid}, Buffer, Window) ->
    Pid ! {body_part, self(), list_to_binary(lists:reverse(Buffer))},
    receive
        {ack, Pid} ->  Window;
        {'DOWN', _, process, Pid, _} -> exit(normal)
    after 0 ->
        lhttpc_lib:dec(Window)
    end.

read_chunked_body(Socket, Ssl, Hdrs, Chunks, Drop, State) ->
    case read_chunk_size(Socket, Ssl) of
        0 ->
            Body = if
                Drop -> <<>>;
                true -> list_to_binary(lists:reverse(Chunks))
            end,
            {_, NewHdrs, State2} = read_trailers(Socket, Ssl, [], Hdrs, State),
            {Body, NewHdrs, State2};
        Size ->
            Chunk = read_chunk(Socket, Ssl, Size, Drop),
            read_chunked_body(Socket, Ssl, Hdrs, [Chunk | Chunks], Drop,
              State)
    end.

chunk_size(Bin) ->
    erlang:list_to_integer(lists:reverse(chunk_size(Bin, [])), 16).

chunk_size(<<$;, _/binary>>, Chars) ->
    Chars;
chunk_size(<<"\r\n", _/binary>>, Chars) ->
    Chars;
chunk_size(<<$\s, Binary/binary>>, Chars) ->
    %% Facebook's HTTP server returns a chunk size like "6  \r\n"
    chunk_size(Binary, Chars);
chunk_size(<<Char, Binary/binary>>, Chars) ->
    chunk_size(Binary, [Char | Chars]).

read_partial_chunk(Socket, Ssl, ChunkSize, ChunkSize) ->
    {read_chunk(Socket, Ssl, ChunkSize, false), 0};
read_partial_chunk(Socket, Ssl, Size, ChunkSize) ->
    ok = lhttpc_sock:setopts(Socket, [{packet, raw}], Ssl),
    case lhttpc_sock:recv(Socket, Size, Ssl) of
        {ok, Chunk} ->
            {Chunk, ChunkSize - Size};
        {error, Reason} ->
            erlang:error(Reason)
    end.

read_chunk(Socket, Ssl, Size, false) ->
    ok = lhttpc_sock:setopts(Socket, [{packet, raw}], Ssl),
    case lhttpc_sock:recv(Socket, Size + 2, Ssl) of
        {ok, <<Chunk:Size/binary, "\r\n">>} ->
            Chunk;
        {ok, Data} ->
            erlang:error({invalid_chunk, Data});
        {error, Reason} ->
            erlang:error(Reason)
    end;
read_chunk(Socket, Ssl, Size, true) ->
    lhttpc_sock:setopts(Socket, [{packet, raw}], Ssl),
    if
        Size =< ?DROP_BLOCK_SIZE ->
            case lhttpc_sock:recv(Socket, Size + 2, Ssl) of
                {ok, <<Chunk:Size/binary, "\r\n">>} ->
                    Chunk;
                {ok, Data} ->
                    erlang:error({invalid_chunk, Data});
                {error, Reason} ->
                    erlang:error(Reason)
            end;
        true ->
            case lhttpc_sock:recv(Socket, ?DROP_BLOCK_SIZE, Ssl) of
                {ok, _} ->
                    read_chunk(Socket, Ssl, Size - ?DROP_BLOCK_SIZE, true);
                {error, Reason} ->
                    erlang:error(Reason)
            end
    end.

read_trailers(Socket, Ssl, Trailers, Hdrs, State) ->
    case lhttpc_sock:recv(Socket, Ssl) of
        {ok, Data} ->
            Decode_More = State#client_state.decode_packet_more,
            Data2 = case Decode_More of
                <<>> -> Data;
                _    -> list_to_binary([Decode_More, Data])
            end,
            State2 = State#client_state{
              decode_packet_more = <<>>
            },
            read_trailers(Socket, Ssl, Trailers, Hdrs, State2, Data2);
        {error, closed} ->
            {Trailers, Hdrs, State};
        {error, Error} ->
            erlang:error(Error)
    end.

read_trailers(Socket, Ssl, Trailers, Hdrs, State, Buffer) ->
    case erlang:decode_packet(httph, Buffer, []) of
        {ok, {http_header, _, Name, _, Value}, NextBuffer} ->
            Header = {Name, Value},
            NTrailers = [Header | Trailers],
            NHeaders = [Header | Hdrs],
            read_trailers(Socket, Ssl, NTrailers, NHeaders, State, NextBuffer);
        {ok, http_eoh, NextBuffer} ->
            lhttpc_sock:unrecv(Socket, NextBuffer),
            {Trailers, Hdrs, State};
        {ok, {http_error, HttpString}, _} ->
            erlang:error({bad_trailer, HttpString});
        {more, _} ->
            case lhttpc_sock:recv(Socket, Ssl) of
                {ok, Data} ->
                    BufferAndData = list_to_binary([Buffer, Data]),
                    read_trailers(Socket, Ssl, Trailers, Hdrs, State, BufferAndData);
                {error, closed} ->
                    erlang:error({bad_trailer, closed});
                {error, Error} ->
                    erlang:error(Error)
            end;
        {error, Error} ->
            erlang:error(Error)
    end.

reply_end_of_body(#client_state{requester = Requester}, Trailers, Hdrs) ->
    Requester ! {http_eob, self(), Trailers},
    {no_return, Hdrs}.

read_partial_infinite_body(State = #client_state{requester = To}, Hdrs, 0) ->
    receive
        {ack, To} ->
            read_partial_infinite_body(State, Hdrs, 1);
        {'DOWN', _, process, To, _} ->
            exit(normal)
    end;
read_partial_infinite_body(State = #client_state{requester = To}, Hdrs, Window)
        when Window >= 0 ->
    case read_infinite_body_part(State) of
        http_eob -> reply_end_of_body(State, [], Hdrs);
        Bin ->
            State#client_state.requester ! {body_part, self(), Bin},
            receive
                {ack, To} ->
                    read_partial_infinite_body(State, Hdrs, Window);
                {'DOWN', _, process, To, _} ->
                    exit(normal)
            after 0 ->
                read_partial_infinite_body(State, Hdrs, lhttpc_lib:dec(Window))
            end
    end.

read_infinite_body_part(#client_state{socket = Socket, ssl = Ssl}) ->
    case lhttpc_sock:recv(Socket, Ssl) of
        {ok, Data} ->
            Data;
        {error, closed} ->
            http_eob;
        {error, Reason} ->
            erlang:error(Reason)
    end.

check_infinite_response({1, Minor}, Hdrs) when Minor >= 1 ->
    HdrValue = lhttpc_lib:header_value("connection", Hdrs, "keep-alive"),
    case string:to_lower(HdrValue) of
        "close" -> ok;
        _       -> erlang:error(no_content_length)
    end;
check_infinite_response(_, Hdrs) ->
    HdrValue = lhttpc_lib:header_value("connection", Hdrs, "close"),
    case string:to_lower(HdrValue) of
        "keep-alive" -> erlang:error(no_content_length);
        _            -> ok
    end.

read_infinite_body(Socket, Hdrs, Ssl, Drop) ->
    read_until_closed(Socket, <<>>, Hdrs, Ssl, Drop).

read_until_closed(Socket, Acc, Hdrs, Ssl, Drop) ->
    case lhttpc_sock:recv(Socket, Ssl) of
        {ok, Body} when Drop =:= false ->
            NewAcc = <<Acc/binary, Body/binary>>,
            read_until_closed(Socket, NewAcc, Hdrs, Ssl, Drop);
        {ok, _} when Drop =:= true ->
            read_until_closed(Socket, Acc, Hdrs, Ssl, Drop);
        {error, closed} ->
            {Acc, Hdrs};
        {error, Reason} ->
            erlang:error(Reason)
    end.

maybe_close_socket(Socket, Ssl, {1, Minor}, ReqHdrs, RespHdrs) when Minor >= 1->
    ClientConnection = ?CONNECTION_HDR(ReqHdrs, "keep-alive"),
    ServerConnection = ?CONNECTION_HDR(RespHdrs, "keep-alive"),
    if
        ClientConnection =:= "close"; ServerConnection =:= "close" ->
            lhttpc_sock:close(Socket, Ssl),
            undefined;
        ClientConnection =/= "close", ServerConnection =/= "close" ->
            Socket
    end;
maybe_close_socket(Socket, Ssl, _, ReqHdrs, RespHdrs) ->
    ClientConnection = ?CONNECTION_HDR(ReqHdrs, "keep-alive"),
    ServerConnection = ?CONNECTION_HDR(RespHdrs, "close"),
    if
        ClientConnection =:= "close"; ServerConnection =/= "keep-alive" ->
            lhttpc_sock:close(Socket, Ssl),
            undefined;
        ClientConnection =/= "close", ServerConnection =:= "keep-alive" ->
            Socket
    end.
