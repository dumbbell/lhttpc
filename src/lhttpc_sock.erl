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
%%% This module implements wrappers for socket operations.
%%% Makes it possible to have the same interface to ssl and tcp sockets.
-module(lhttpc_sock).

-export([
        resolve_host/1,
        connect/5,
        recv/2,
        recv/3,
        unrecv/2,
        send/3,
        controlling_process/3,
        setopts/3,
        close/2,
        get_stat/2,
        reset_stats/1
    ]).

-include("lhttpc_types.hrl").

-spec resolve_host(list()) -> {ok, tuple(), atom()} | {error, term()}.
resolve_host(Host) ->
    case inet_parse:address(Host) of
        {ok, IP_Addr} ->
            {ok, IP_Addr};
        _ ->
            case inet:getaddr(Host, inet) of
                {ok, IP_Addr}   -> {ok, IP_Addr};
                {error, Reason} -> {error, Reason}
            end
    end.

%% @spec (Host, Port, Options, Timeout, SslFlag) -> {ok, Socket} | {error, Reason}
%%   Host = string() | ip_address()
%%   Port = integer()
%%   Options = [{atom(), term()} | atom()]
%%   Timeout = infinity | integer()
%%   SslFlag = boolean()
%%   Socket = {socket(), boolean()}
%%   Reason = atom()
%% @doc
%% Connects to `Host' and `Port'.
%% Will use the `ssl' module if `SslFlag' is `true' and gen_tcp otherwise.
%% `Options' are the normal `gen_tcp' or `ssl' Options.
%% @end
-spec connect(host(), integer(), socket_options(), timeout(), boolean()) ->
    {ok, {socket(), boolean()}} | {error, atom()}.
connect(Host, Port, Options, Timeout, Ssl) ->
    Options2 = Options -- [gather_stats],
    case connect2(Host, Port, Options2, Timeout, Ssl) of
        {ok, Socket} ->
            case lists:member(gather_stats, Options) of
                true ->
                    % This ETS table entry is used by unrecv/2 to store
                    % "unreceived" data and some statistics:
                    % {socket(), Unreceived, Bytes_Sent, Bytes_Recv}
                    State = {Socket, <<>>, 0, 0},
                    ets:insert(lhttpc_sock_states, State),
                    {ok, {Socket, true}};
                false ->
                    {ok, {Socket, false}}
            end;
        Other ->
            Other
    end.

connect2(Host, Port, Options, Timeout, true) ->
    ssl:connect(Host, Port, Options, Timeout);
connect2(Host, Port, Options, Timeout, false) ->
    gen_tcp:connect(Host, Port, Options, Timeout).

%% @spec (Socket, SslFlag) -> {ok, Data} | {error, Reason}
%%   Socket = {socket(), boolean()}
%%   Length = integer()
%%   SslFlag = boolean()
%%   Data = term()
%%   Reason = atom()
%% @doc
%% Reads available bytes from `Socket'.
%% Will block untill data is available on the socket and return the first
%% packet.
%% @end
-spec recv({socket(), boolean()}, boolean()) ->
    {ok, any()} | {error, atom()} | {error, {http_error, string()}}.
recv({Socket, false}, Ssl) ->
    recv2(Socket, 0, Ssl);
recv({Socket, true}, Ssl) ->
    [{_, Previous_Data, Sent, Received}] = ets:lookup(lhttpc_sock_states,
      Socket),
    case Previous_Data of
        <<>> ->
            case recv2(Socket, 0, Ssl) of
                {ok, Data} ->
                    State = {Socket, <<>>, Sent, Received + size(Data)},
                    ets:insert(lhttpc_sock_states, State),
                    {ok, Data};
                {error, Reason} ->
                    {error, Reason}
            end;
        _ ->
            State = {Socket, <<>>, Sent, Received + size(Previous_Data)},
            ets:insert(lhttpc_sock_states, State),
            {ok, Previous_Data}
    end.

%% @spec (Socket, Length, SslFlag) -> {ok, Data} | {error, Reason}
%%   Socket = {socket(), boolean()}
%%   Length = integer()
%%   SslFlag = boolean()
%%   Data = term()
%%   Reason = atom()
%% @doc
%% Receives `Length' bytes from `Socket'.
%% Will block untill `Length' bytes is available.
%% @end
-spec recv({socket(), boolean()}, integer(), boolean()) -> {ok, any()} | {error, atom()}.
recv(_, 0, _) ->
    {ok, <<>>};
recv({Socket, false}, Length, Ssl) ->
    recv2(Socket, Length, Ssl);
recv({Socket, true}, Length, Ssl) ->
    [{_, Previous_Data, Sent, Received}] = ets:lookup(lhttpc_sock_states,
      Socket),
    Previous_Length = size(Previous_Data),
    if
        Length < Previous_Length ->
            <<Data:Length/binary, Previous_Data2/binary>> = Previous_Data,
            State = {Socket, Previous_Data2, Sent, Received + Length},
            ets:insert(lhttpc_sock_states, State),
            {ok, Data};
        Length == Previous_Length ->
            State = {Socket, <<>>, Sent, Received + Length},
            ets:insert(lhttpc_sock_states, State),
            {ok, Previous_Data};
        true ->
            case recv2(Socket, Length - Previous_Length, Ssl) of
                {ok, Data} ->
                    State = {Socket, <<>>, Sent, Received + Length},
                    ets:insert(lhttpc_sock_states, State),
                    {ok, <<Previous_Data/binary, Data/binary>>};
                {error, Reason} ->
                    % We adopt the same behaviour as gen_tcp:recv/2: if
                    % an error occurs while reading, less than Length
                    % bytes of data maybe discarded.
                    {error, Reason}
            end
    end.

recv2(Socket, Length, true) ->
    ssl:recv(Socket, Length);
recv2(Socket, Length, false) ->
    gen_tcp:recv(Socket, Length).

%% @spec (Socket, Data) -> ok
%%   Socket = {socket(), boolean()}
%%   Data = term()
%% @doc
%% Put data back in the receive buffer. Those data will be served with the next
%% recv/{2,3}.
%%
%% Note that this function is only available when the "gather_stats" option was
%% given at connection time.
%% @end
-spec unrecv({socket(), boolean()}, binary()) -> ok.
unrecv({_, false}, _) ->
    throw(badarg);
unrecv(_, <<>>) ->
    ok;
unrecv({Socket, true}, Data) ->
    [{_, Previous_Data, Sent, Received}] = ets:lookup(lhttpc_sock_states,
      Socket),
    New_Data = <<Data/binary, Previous_Data/binary>>,
    State    = {Socket, New_Data, Sent, Received - size(Data)},
    ets:insert(lhttpc_sock_states, State),
    ok.

%% @spec (Socket, Data, SslFlag) -> ok | {error, Reason}
%%   Socket = {socket(), boolean()}
%%   Data = iolist()
%%   SslFlag = boolean()
%%   Reason = atom()
%% @doc
%% Sends data on a socket.
%% Will use the `ssl' module if `SslFlag' is set to `true', otherwise the
%% gen_tcp module.
%% @end
-spec send({socket(), boolean()}, iolist() | binary(), boolean()) -> ok | {error, atom()}.
send({Socket, Gather_Stats}, Request, true) ->
    Ret = ssl:send(Socket, Request),
    send2(Socket, Gather_Stats, Request, Ret);
send({Socket, Gather_Stats}, Request, false) ->
    Ret = gen_tcp:send(Socket, Request),
    send2(Socket, Gather_Stats, Request, Ret).

send2(_, false, _, Ret) ->
    Ret;
send2(Socket, true, Request, ok) ->
    [{_, Previous_Data, Sent, Received}] = ets:lookup(lhttpc_sock_states,
      Socket),
    State = {Socket, Previous_Data, Sent + iolist_size(Request), Received},
    ets:insert(lhttpc_sock_states, State),
    ok;
send2(_, true, _, Ret) ->
    Ret.

%% @spec (Socket, Pid, SslFlag) -> ok | {error, Reason}
%%   Socket = {socket(), boolean()}
%%   Pid = pid()
%%   SslFlag = boolean()
%%   Reason = atom()
%% @doc
%% Sets the controlling proces for the `Socket'.
%% @end
-spec controlling_process({socket(), boolean()}, pid(), boolean()) ->
    ok | {error, atom()}.
controlling_process({Socket, _}, Pid, true) ->
    ssl:controlling_process(Socket, Pid);
controlling_process({Socket, _}, Pid, false) ->
    gen_tcp:controlling_process(Socket, Pid).

%% @spec (Socket, Options, SslFlag) -> ok | {error, Reason}
%%   Socket = {socket(), boolean()}
%%   Options = [atom() | {atom(), term()}]
%%   SslFlag = boolean()
%%   Reason = atom()
%% @doc
%% Sets options for a socket. Look in `inet:setopts/2' for more info.
%% @end
-spec setopts({socket(), boolean()}, socket_options(), boolean()) ->
    ok | {error, atom()}.
setopts({Socket, _}, Options, true) ->
    ssl:setopts(Socket, Options);
setopts({Socket, _}, Options, false) ->
    inet:setopts(Socket, Options).

%% @spec (Socket, SslFlag) -> ok | {error, Reason}
%%   Socket = {socket(), boolean()}
%%   SslFlag = boolean()
%%   Reason = atom()
%% @doc
%% Closes a socket.
%% @end
-spec close({socket(), boolean()}, boolean()) -> ok | {error, atom()}.
close({Socket, Gather_Stats}, true) ->
    Ret = ssl:close(Socket),
    close2(Socket, Gather_Stats, Ret);
close({Socket, Gather_Stats}, false) ->
    Ret = gen_tcp:close(Socket),
    close2(Socket, Gather_Stats, Ret).

close2(_, false, Ret) ->
    Ret;
close2(Socket, true, Ret) ->
    ets:delete(lhttpc_sock_states, Socket),
    Ret.

%% @spec (Socket, Type) -> Stat
%%   Socket = {socket(), boolean()}
%%   Type = bytes_sent | bytes_received
%%   Stat = integer()
%% @doc
%% Return the number of bytes sent or received.
%% @end
-spec get_stat({socket(), boolean()}, bytes_sent | bytes_received) -> non_neg_integer().
get_stat({_, false}, _) ->
    0;
get_stat({Socket, true}, Type) ->
    [{_, _, Sent, Received}] = ets:lookup(lhttpc_sock_states, Socket),
    case Type of
        bytes_sent     -> Sent;
        bytes_received -> Received
    end.

%% @spec (Socket) -> ok
%%   Socket = {socket(), boolean()}
%% @doc
%% Reset already statistics to zero.
%% @end.
-spec reset_stats({socket(), boolean()}) -> ok.
reset_stats({_, false}) ->
    ok;
reset_stats({Socket, true}) ->
    [{_, Previous_Data, _, _}] = ets:lookup(lhttpc_sock_states,
      Socket),
    State = {Socket, Previous_Data, 0, 0},
    ets:insert(lhttpc_sock_states, State),
    ok.
