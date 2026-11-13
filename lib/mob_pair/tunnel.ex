defmodule MobPair.Tunnel do
  @moduledoc """
  TLS distribution to FMutate without restarting Humdinger's BEAM.

  FMutate listens with stock `-proto_dist inet_tls` when another phone may
  connect (protocol §2). Humdinger can't choose its own carrier that way: on
  Android distribution starts at runtime (`Mob.Dist`), and `-proto_dist` is an
  init argument read once at boot, so it would take a relaunch after pairing.
  Humdinger's node stays on plain `inet_tcp_dist` and this tunnel carries it:

    1. `open/2` connects to FMutate's distribution port with TLS 1.3, pinning
       FMutate's certificate (`fp`): nothing goes to any other peer. It
       presents Humdinger's client certificate from the pairing; FMutate
       aborts the session unless it pinned that certificate (in TLS 1.3 that
       happens just after `open/2` returns, and the distribution handshake
       then fails).
    2. It listens on a loopback port; `MobPair.Epmd` routes FMutate's
       node there, so `net_kernel` connects to the tunnel.
    3. It accepts exactly one connection, and only from a socket in this BEAM
       (another app on the phone could otherwise borrow the TLS session):
       others are closed and it keeps waiting, then it closes the listener.
    4. It forwards bytes both ways. The only difference between the two
       carriers' wire formats is the handshake framing: `inet_tcp_dist` frames
       handshake messages with a 2-byte length and `inet_tls_dist` with a
       4-byte one (both use 4 bytes afterwards). The tunnel reframes each
       handshake message until the sibling's last one (`r`, the challenge
       reply) going out and FMutate's last one (`a`, the challenge ack) coming
       back, then passes the streams through untouched.

  The tunnel lives as long as the distribution connection and dies with
  `owner`.
  """

  alias MobPair.Cert

  @connect_timeout 5_000
  # net_kernel connects right after open/2 returns; give it its setup time.
  @accept_timeout 10_000

  @type endpoint :: %{
          host: String.t(),
          dist_port: :inet.port_number(),
          fp: <<_::256>>,
          cert: binary(),
          key: binary()
        }

  @doc """
  Connects to FMutate over TLS and returns the tunnel and its loopback port.
  Errors: `{:tls, reason}` (unreachable, or a certificate didn't match), or a
  listen error.
  """
  @spec open(endpoint(), pid()) :: {:ok, pid(), :inet.port_number()} | {:error, term()}
  def open(%{host: host, dist_port: port, fp: fp, cert: cert, key: key}, owner) do
    {:ok, ip} = :inet.parse_strict_address(String.to_charlist(host))

    ssl_options = [
      verify: :verify_peer,
      cacerts: [],
      verify_fun: Cert.verify_fun(fp),
      certs_keys: [Cert.ssl_cert_key(cert, key)],
      versions: [:"tlsv1.3"],
      server_name_indication: :disable,
      mode: :binary,
      packet: :raw,
      active: false,
      nodelay: true
    ]

    with {:ok, _} <- Application.ensure_all_started(:ssl),
         {:ok, tls} <- tls_connect(ip, port, ssl_options),
         {:ok, listen} <- listen(tls),
         {:ok, local_port} <- :inet.port(listen) do
      pid = :proc_lib.spawn(fn -> init(owner) end)
      :ok = :ssl.controlling_process(tls, pid)
      :ok = :gen_tcp.controlling_process(listen, pid)
      send(pid, {:sockets, listen, tls})
      {:ok, pid, local_port}
    end
  end

  @doc "Closes the tunnel (and with it the distribution connection)."
  @spec close(pid()) :: :ok
  def close(pid) do
    Process.exit(pid, :shutdown)
    :ok
  end

  defp tls_connect(ip, port, options) do
    case :ssl.connect(ip, port, options, @connect_timeout) do
      {:ok, tls} -> {:ok, tls}
      {:error, reason} -> {:error, {:tls, reason}}
    end
  end

  defp listen(tls) do
    case :gen_tcp.listen(0, [
           :binary,
           ip: {127, 0, 0, 1},
           active: false,
           nodelay: true,
           backlog: 4
         ]) do
      {:ok, listen} ->
        {:ok, listen}

      {:error, _} = error ->
        :ssl.close(tls)
        error
    end
  end

  defp init(owner) do
    receive do
      {:sockets, listen, tls} ->
        Process.monitor(owner)
        deadline = System.monotonic_time(:millisecond) + @accept_timeout

        with {:ok, tcp} <- accept_own(listen, deadline),
             :ok <- :gen_tcp.close(listen) do
          :ok = :inet.setopts(tcp, active: :once)
          :ok = :ssl.setopts(tls, active: :once)
          loop(%{tcp: tcp, tls: tls, out: {:handshake, ""}, in: {:handshake, ""}})
        end
    end
  end

  # Another app on the phone may connect first: close it and keep waiting
  # for this BEAM's connection until the deadline.
  defp accept_own(listen, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)

    with true <- remaining > 0 || {:error, :timeout},
         {:ok, tcp} <- :gen_tcp.accept(listen, remaining) do
      if own_socket?(tcp) do
        {:ok, tcp}
      else
        :gen_tcp.close(tcp)
        accept_own(listen, deadline)
      end
    end
  end

  defp loop(%{tcp: tcp, tls: tls} = state) do
    receive do
      {:tcp, ^tcp, data} ->
        out = forward_out(tls, state.out, data)
        :ok = :inet.setopts(tcp, active: :once)
        loop(%{state | out: out})

      {:ssl, ^tls, data} ->
        incoming = forward_in(tcp, state.in, data)
        :ok = :ssl.setopts(tls, active: :once)
        loop(%{state | in: incoming})

      {closed, _socket} when closed in [:tcp_closed, :ssl_closed] ->
        close_sockets(state)

      {error, _socket, _reason} when error in [:tcp_error, :ssl_error] ->
        close_sockets(state)

      {:DOWN, _ref, :process, _owner, _reason} ->
        close_sockets(state)
    end
  end

  defp close_sockets(%{tcp: tcp, tls: tls}) do
    :gen_tcp.close(tcp)
    :ssl.close(tls)
  end

  # Sibling → FMutate: 2-byte handshake frames become 4-byte ones until the
  # challenge reply (`r`) has gone out.
  defp forward_out(tls, {:stream, _}, data) do
    :ok = :ssl.send(tls, data)
    {:stream, ""}
  end

  defp forward_out(tls, {:handshake, buffer}, data) do
    case buffer <> data do
      <<len::16, message::binary-size(len), rest::binary>> ->
        :ok = :ssl.send(tls, <<len::32, message::binary>>)
        next = if match?(<<?r, _::binary>>, message), do: :stream, else: :handshake
        forward_more(&forward_out(tls, &1, &2), next, rest)

      partial ->
        {:handshake, partial}
    end
  end

  # FMutate → sibling: 4-byte handshake frames become 2-byte ones until the
  # challenge ack (`a`) has come back.
  defp forward_in(tcp, {:stream, _}, data) do
    :ok = :gen_tcp.send(tcp, data)
    {:stream, ""}
  end

  defp forward_in(tcp, {:handshake, buffer}, data) do
    case buffer <> data do
      <<len::32, message::binary-size(len), rest::binary>> when len < 65_536 ->
        :ok = :gen_tcp.send(tcp, <<len::16, message::binary>>)
        next = if match?(<<?a, _::binary>>, message), do: :stream, else: :handshake
        forward_more(&forward_in(tcp, &1, &2), next, rest)

      <<len::32, _::binary>> when len >= 65_536 ->
        exit(:bad_handshake_frame)

      partial ->
        {:handshake, partial}
    end
  end

  defp forward_more(_forward, phase, ""), do: {phase, ""}
  defp forward_more(forward, phase, rest), do: forward.({phase, ""}, rest)

  # The connection must come from this BEAM: some local TCP port of ours has
  # the accepted socket's peer address as its own address.
  defp own_socket?(tcp) do
    with {:ok, peer} <- :inet.peername(tcp) do
      Enum.any?(:erlang.ports(), fn port ->
        port != tcp and :erlang.port_info(port, :name) == {:name, ~c"tcp_inet"} and
          :inet.sockname(port) == {:ok, peer}
      end)
    end
  end
end
