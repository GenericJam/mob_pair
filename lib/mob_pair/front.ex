defmodule MobPair.Front do
  @moduledoc """
  TLS distribution for a host whose node runs plain `inet_tcp` on loopback.

  A sibling on another phone must reach the host over TLS (mutual TLS 1.3,
  both certificates pinned; protocol §2). A host can listen that way with
  stock `-proto_dist inet_tls`, but `-proto_dist` is an init argument: a Mob
  app that starts distribution at runtime (FMutate's `Node.start/2` a few
  seconds after launch) can't pick it without relaunching, and its loopback
  listener also serves same-phone siblings and development tools. The front
  is the host-side mirror of `MobPair.Tunnel`:

    1. It listens with TLS 1.3 on the `:ip` it is given, presents the
       host's certificate and requires a client certificate that a pairing
       pinned (`node_for_fp`, default `MobPair.Pairings.node_for_fp/1`).
       Anything else fails the TLS handshake.
    2. It reads the sibling's first distribution handshake message (`N`, or
       the old `n`) and checks that the node name it declares is the name
       paired with that certificate. A sibling can't borrow another pairing's
       name (it would still need that pairing's cookie; this check makes the
       certificate and the name one credential).
    3. It connects to the node's loopback listener and forwards bytes both
       ways, reframing the handshake: `inet_tls_dist` frames handshake
       messages with a 4-byte length, `inet_tcp_dist` with a 2-byte one
       (both use 4 bytes afterwards). Sibling → node until the sibling's
       challenge reply (`r`), node → sibling until the node's challenge ack
       (`a`); then the streams pass through untouched.

  The node then sees an ordinary loopback connection under the paired name
  and checks its per-node cookie as usual. Revoking a pairing makes its
  certificate unknown here (new connections fail) and the host disconnects
  the node (which closes the forwarded connection).

  It listens only where told: `:ip` is required (the Wi-Fi address, as
  `MobPair.Host` chooses it; `{0, 0, 0, 0}` only when the caller really means
  every interface, mobile data and VPN included).

  At most `:max_connections` (default 8) forwarded connections are served at
  once. Before that, new connections are rate limited (`:accept_rate`,
  default 40 at once then one per 100 ms; `:accept_rate_per_source`, default
  10 at once then one per second from one address), at most 8 connections
  may be in their TLS handshake or first message (2 per source address), and
  each must send its first handshake message within 10 s, so a peer without
  a pinned certificate can't hold the slots of paired siblings. A connection
  over a limit is closed by the accept loop before anything is spawned for
  it.
  """

  use GenServer

  alias MobPair.Cert

  @handshake_timeout 10_000
  @max_connections 8
  @max_handshakes 8
  @max_per_source 2
  @accept_rate {40, 100}
  @accept_rate_per_source {10, 1_000}
  @max_handshake_frame 65_535

  @doc """
  Starts the front. Options: `:cert` (the host's `MobPair.Cert`, required),
  `:target` (`{ip, port}` of the node's plain listener, required), `:ip`
  (the listen address, required), `:port` (default 0, any), `:node_for_fp`
  (a function from a client certificate's SHA-256 to the paired node name,
  or nil), `:max_connections`, `:accept_rate` and `:accept_rate_per_source`
  (`{burst, interval_ms}`), `:name`.

  Raises `ArgumentError` without `:ip`.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    if not is_tuple(Keyword.get(opts, :ip)) do
      raise ArgumentError,
            "MobPair.Front needs :ip, the address to listen on (the Wi-Fi address; " <>
              "{0, 0, 0, 0} only to listen on every interface, mobile data and VPN included)"
    end

    case Keyword.fetch(opts, :name) do
      {:ok, name} -> GenServer.start_link(__MODULE__, opts, name: name)
      :error -> GenServer.start_link(__MODULE__, opts)
    end
  end

  @doc "The port the front listens on."
  @spec port(GenServer.server()) :: :inet.port_number()
  def port(server), do: GenServer.call(server, :port)

  @doc "Stops the front; forwarded connections close with it."
  @spec stop(GenServer.server()) :: :ok
  def stop(server), do: GenServer.stop(server)

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)
    cert = Keyword.fetch!(opts, :cert)
    node_for_fp = Keyword.get(opts, :node_for_fp, &MobPair.Pairings.node_for_fp/1)

    # The listener is plain TCP: a connection is admitted (or closed) before
    # any TLS work, and TLS starts on it in its own process (serve/4).
    tls_options = [
      certs_keys: [Cert.ssl_cert_key(cert.cert, cert.key)],
      verify: :verify_peer,
      fail_if_no_peer_cert: true,
      cacerts: [],
      verify_fun: Cert.verify_fun(&(node_for_fp.(&1) != nil)),
      versions: [:"tlsv1.3"],
      mode: :binary,
      packet: :raw,
      active: false
    ]

    listen_options = [
      :binary,
      ip: Keyword.fetch!(opts, :ip),
      reuseaddr: true,
      packet: :raw,
      active: false,
      nodelay: true
    ]

    with {:ok, _} <- Application.ensure_all_started(:ssl),
         {:ok, listen} <- :gen_tcp.listen(Keyword.get(opts, :port, 0), listen_options),
         {:ok, port} <- :inet.port(listen) do
      server = self()
      acceptor = spawn_link(fn -> accept_loop(server, listen) end)

      {:ok,
       %{
         listen: listen,
         port: port,
         acceptor: acceptor,
         tls_options: tls_options,
         target: Keyword.fetch!(opts, :target),
         node_for_fp: node_for_fp,
         max: Keyword.get(opts, :max_connections, @max_connections),
         admission:
           MobPair.Admission.new(
             Keyword.get(opts, :accept_rate, @accept_rate),
             Keyword.get(opts, :accept_rate_per_source, @accept_rate_per_source)
           ),
         connections: %{},
         handshakes: %{}
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, state.port, state}

  # From the accept loop, before anything runs for the connection: the
  # connection rate (globally and from this address), then a bounded number
  # of handshakes, few per source address. Admitted, the connection gets its
  # own process, linked (it dies with the front) and monitored.
  def handle_call({:admit, ip}, _from, state) do
    from_ip = Enum.count(state.handshakes, &match?({_pid, {_ref, ^ip}}, &1))

    with true <- map_size(state.handshakes) < @max_handshakes and from_ip < @max_per_source,
         {:ok, admission} <- MobPair.Admission.take(state.admission, ip) do
      %{tls_options: tls_options, target: target, node_for_fp: node_for_fp} = state
      server = self()

      handler =
        spawn_link(fn ->
          receive do
            {:go, socket} -> serve(server, socket, tls_options, {target, node_for_fp})
          end
        end)

      handshakes = Map.put(state.handshakes, handler, {Process.monitor(handler), ip})
      {:reply, {:ok, handler}, %{state | admission: admission, handshakes: handshakes}}
    else
      _ -> {:reply, :busy, state}
    end
  end

  # The pinned certificate and its name checked: a forwarded connection.
  def handle_call({:established, pid}, _from, state) do
    case Map.pop(state.handshakes, pid) do
      {{ref, _ip}, handshakes} when map_size(state.connections) < state.max ->
        {:reply, :ok,
         %{state | handshakes: handshakes, connections: Map.put(state.connections, pid, ref)}}

      _ ->
        {:reply, :busy, state}
    end
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, state),
    do:
      {:noreply,
       %{
         state
         | connections: Map.delete(state.connections, pid),
           handshakes: Map.delete(state.handshakes, pid)
       }}

  def handle_info({:EXIT, pid, reason}, %{acceptor: pid} = state), do: {:stop, reason, state}
  def handle_info({:EXIT, _pid, _reason}, state), do: {:noreply, state}

  # The TLS options hold the host's private key: keep it out of crash
  # reports and :sys.get_status/1.
  @impl true
  def format_status(status) do
    Map.update(status, :state, nil, fn
      %{tls_options: _} = state -> %{state | tls_options: :redacted}
      other -> other
    end)
  end

  @impl true
  def terminate(_reason, state) do
    :gen_tcp.close(state.listen)

    for {pid, _} <- Map.merge(state.connections, state.handshakes),
        do: Process.exit(pid, :shutdown)

    :ok
  end

  # Each connection is admitted (see handle_call({:admit, ip}, ...)) before
  # anything is spawned for it; one over a limit is closed here. The loop
  # accepts nothing more until the front has answered.
  defp accept_loop(server, listen) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        with {:ok, {ip, _port}} <- :inet.peername(socket),
             {:ok, handler} <- GenServer.call(server, {:admit, ip}, :infinity) do
          case :gen_tcp.controlling_process(socket, handler) do
            :ok -> send(handler, {:go, socket})
            {:error, _} -> Process.exit(handler, :kill)
          end
        else
          _busy -> :gen_tcp.close(socket)
        end

        accept_loop(server, listen)

      {:error, :closed} ->
        :ok

      {:error, _} ->
        accept_loop(server, listen)
    end
  end

  # One sibling connection, in its own process (admitted by the front). A
  # refused one ends here; its sockets close with the process.
  defp serve(server, socket, tls_options, {target, node_for_fp}) do
    Process.monitor(server)

    with {:ok, tls} <- :ssl.handshake(socket, tls_options, @handshake_timeout),
         {:ok, expected} <- paired_node(tls, node_for_fp),
         {:ok, first, rest} <- first_message(tls),
         :ok <- same_name(first, expected),
         :ok <- GenServer.call(server, {:established, self()}),
         {:ok, tcp} <- connect(target) do
      :ok = :gen_tcp.send(tcp, <<byte_size(first)::16, first::binary>>)
      to_node = after_message(first, ?r)
      to_node = if rest == "", do: to_node, else: forward_in(tcp, to_node, rest)
      :ok = :inet.setopts(tcp, active: :once)
      :ok = :ssl.setopts(tls, active: :once)
      loop(%{tcp: tcp, tls: tls, in: to_node, out: {:handshake, ""}})
    end
  end

  # The handshake accepted a pinned certificate; look its pairing up again
  # (it may have been revoked in between) to know which name it may use.
  defp paired_node(tls, node_for_fp) do
    with {:ok, der} <- :ssl.peercert(tls) do
      case node_for_fp.(Cert.fingerprint(der)) do
        nil -> {:error, :not_paired}
        node -> {:ok, node}
      end
    end
  end

  defp first_message(tls), do: first_message(tls, "", deadline())

  defp first_message(tls, buffer, deadline) do
    case buffer do
      <<len::32, message::binary-size(len), rest::binary>> when len <= @max_handshake_frame ->
        {:ok, message, rest}

      <<len::32, _::binary>> when len > @max_handshake_frame ->
        {:error, :bad_handshake_frame}

      partial ->
        remaining = deadline - System.monotonic_time(:millisecond)

        with true <- remaining > 0 || {:error, :timeout},
             {:ok, data} <- :ssl.recv(tls, 0, remaining) do
          first_message(tls, partial <> data, deadline)
        end
    end
  end

  defp deadline, do: System.monotonic_time(:millisecond) + @handshake_timeout

  # send_name: `N` (flags, creation, name length, name; OTP 23+) or the old
  # `n` (version, flags, name).
  defp same_name(
         <<?N, _flags::64, _creation::32, len::16, name::binary-size(len), _::binary>>,
         expected
       ),
       do: if(name == expected, do: :ok, else: {:error, :wrong_name})

  defp same_name(<<?n, _version::16, _flags::32, name::binary>>, expected),
    do: if(name == expected, do: :ok, else: {:error, :wrong_name})

  defp same_name(_message, _expected), do: {:error, :bad_handshake}

  defp connect({ip, port}),
    do: :gen_tcp.connect(ip, port, [:binary, active: false, nodelay: true], @handshake_timeout)

  defp loop(%{tcp: tcp, tls: tls} = state) do
    receive do
      {:ssl, ^tls, data} ->
        to_node = forward_in(tcp, state.in, data)
        :ok = :ssl.setopts(tls, active: :once)
        loop(%{state | in: to_node})

      {:tcp, ^tcp, data} ->
        out = forward_out(tls, state.out, data)
        :ok = :inet.setopts(tcp, active: :once)
        loop(%{state | out: out})

      {closed, _socket} when closed in [:tcp_closed, :ssl_closed] ->
        close(state)

      {error, _socket, _reason} when error in [:tcp_error, :ssl_error] ->
        close(state)

      {:DOWN, _ref, :process, _server, _reason} ->
        close(state)
    end
  end

  defp close(%{tcp: tcp, tls: tls}) do
    :gen_tcp.close(tcp)
    :ssl.close(tls)
  end

  defp after_message(<<tag, _::binary>>, tag), do: {:stream, ""}
  defp after_message(_message, _tag), do: {:handshake, ""}

  # Sibling → node: 4-byte handshake frames become 2-byte ones until the
  # sibling's challenge reply (`r`) has gone through.
  defp forward_in(tcp, {:stream, _}, data) do
    :ok = :gen_tcp.send(tcp, data)
    {:stream, ""}
  end

  defp forward_in(tcp, {:handshake, buffer}, data) do
    case buffer <> data do
      <<len::32, message::binary-size(len), rest::binary>> when len <= @max_handshake_frame ->
        :ok = :gen_tcp.send(tcp, <<len::16, message::binary>>)
        more(&forward_in(tcp, &1, &2), after_message(message, ?r), rest)

      <<len::32, _::binary>> when len > @max_handshake_frame ->
        exit(:bad_handshake_frame)

      partial ->
        {:handshake, partial}
    end
  end

  # Node → sibling: 2-byte handshake frames become 4-byte ones until the
  # node's challenge ack (`a`) has gone through.
  defp forward_out(tls, {:stream, _}, data) do
    :ok = :ssl.send(tls, data)
    {:stream, ""}
  end

  defp forward_out(tls, {:handshake, buffer}, data) do
    case buffer <> data do
      <<len::16, message::binary-size(len), rest::binary>> ->
        :ok = :ssl.send(tls, <<len::32, message::binary>>)
        more(&forward_out(tls, &1, &2), after_message(message, ?a), rest)

      partial ->
        {:handshake, partial}
    end
  end

  defp more(_forward, phase, ""), do: phase
  defp more(forward, phase, rest), do: forward.(phase, rest)
end
