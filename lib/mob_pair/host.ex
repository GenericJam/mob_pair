defmodule MobPair.Host do
  @moduledoc """
  The host app's pairing endpoint (FMutate protocol §1.1–1.5): what runs
  while the host's "Pair an app" screen is open, in the host app (FMutate,
  Magpie…).

  It holds one pairing secret, shown as a code (`code/1`, `KQ7M-X2PD`) and a
  link (`link/1`, the QR payload, see `MobPair.Link`), both single use,
  valid for 5 minutes and invalidated after 5 failed attempts (wrong codes
  and wrong tokens count alike); `renew/1` is "New code". `info/1` has what
  the screen shows (code, link, status, attempts left, time left), and
  `:notify` gets `{:mob_pair_secret, server, status}` whenever the secret
  changes (a failed attempt, used, too many attempts, renewed; expiry is
  seen through `info/1`).

  It listens with TLS 1.3 presenting the host's certificate, runs the
  exchange of §1.5 with each sibling (token or SRP-6a, with the `:service`
  identity), asks the user (`:approve`), and on Allow registers the sibling
  with `:pairings` (`MobPair.Pairings`) and returns the grant. With
  `:advertise` it also announces itself over mDNS (`MobPair.Responder`,
  `_<service>._tcp.local`) with the TXT keys of §1.5; when the responder
  can't start (on Android the system owns port 5353) it runs on without
  mDNS and logs a warning (`info/1`'s `advertising` is false).

  Stopping the server stops pairing and advertising. Siblings that connect
  from loopback are granted `127.0.0.1` and `:loopback_dist`; others get
  `:dist_host`, `:dist_port` and always `inet_tls`. With
  `dist_proto: :inet_tcp` (the host's plain listener on loopback, see
  `MobPair.boot_args/1`) only siblings on the same phone can pair: others
  get `loopback_only` before they spend an attempt, and a non-loopback
  `:dist_host` refuses to start. At most 8 connections are handled at once.

  The approval hook is `:approve`: a function of the request returning
  `:allow` or `:deny` (it runs in the connection's process and may block), or
  `{:ask, pid}`, which sends `pid`
  `{:mob_pair_request, server, ref, request}` and waits for
  `decide(server, ref, :allow | :deny)`; if the sibling hangs up first,
  `pid` gets `{:mob_pair_withdrawn, server, ref}`. The request is
  `%{app_id, app_name, device_name, node, client_fp, remote_ip, replaces}`:
  the names are what the sibling says (control and format characters
  removed; a sibling on another phone can claim any name), and `replaces` is
  `%{app_name, device_name, paired_at}` of an existing pairing under the same
  node name with another certificate (Allow replaces it), else nil. The
  host's own node name and any `<service>_*` name are refused (`bad_node`).
  """

  use GenServer

  alias MobPair.{Cert, Code, Link, Record, Responder, Srp, Wire}

  require Logger

  @ttl 300_000
  @max_attempts 5
  @step_timeout 30_000
  @decision_timeout 120_000
  @max_handshakes 8

  @doc """
  Options: `:service` (the host's service name, required), `:cert` (the
  host's `MobPair.Cert`, required), `:dist_port` (required), `:dist_proto`
  (`:inet_tls` default, or `:inet_tcp`: same-phone siblings only),
  `:dist_host` (default `:host`), `:loopback_dist` (`%{port, proto}` granted
  to siblings on the same phone, default `%{port: dist_port, proto:
  dist_proto}`), `:inst` (`"a"`), `:name` (`"<Service> <INST>"`), `:device`,
  `:firmware` (the detail line siblings show), `:node` (the host's node
  name, default `node()`), `:ip` / `:port` to listen on (`{0, 0, 0, 0}`, 0),
  `:host` (the address put in the link; default the first non-loopback IPv4
  address), `:ttl` (ms), `:max_attempts`, `:approve`, `:notify` (a pid),
  `:pairings` (a module with `add/1` and `get/1`, default
  `MobPair.Pairings`), `:advertise` (Responder options such as `:bind`, or
  `false`), `:server_name`.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    case Keyword.fetch(opts, :server_name) do
      {:ok, name} -> GenServer.start_link(__MODULE__, opts, name: name)
      :error -> GenServer.start_link(__MODULE__, opts)
    end
  end

  @doc "The code to show, `KQ7M-X2PD`."
  @spec code(GenServer.server()) :: String.t()
  def code(server), do: GenServer.call(server, :code)

  @doc "The link to show as a QR code and under Copy link."
  @spec link(GenServer.server()) :: String.t()
  def link(server), do: GenServer.call(server, :link)

  @doc "The pairing port."
  @spec port(GenServer.server()) :: :inet.port_number()
  def port(server), do: GenServer.call(server, :port)

  @typedoc "What `info/1` returns."
  @type info :: %{
          code: String.t(),
          link: String.t(),
          port: :inet.port_number(),
          status: :open | :used | :invalid | :expired,
          attempts_left: non_neg_integer(),
          expires_in: non_neg_integer(),
          advertising: boolean()
        }

  @doc """
  The secret's state for the Pair screen: the code and link to show, the
  status (`:open`, `:used` once a sibling got in, `:invalid` after too many
  failed attempts, `:expired`), the attempts left, the ms until it expires
  (0 when expired), and whether mDNS advertising runs.
  """
  @spec info(GenServer.server()) :: info()
  def info(server), do: GenServer.call(server, :info)

  @doc "The mDNS responder advertising this endpoint (`:advertise`), or nil."
  @spec responder(GenServer.server()) :: pid() | nil
  def responder(server), do: GenServer.call(server, :responder)

  @doc "New code: a fresh secret, attempts reset."
  @spec renew(GenServer.server()) :: :ok
  def renew(server), do: GenServer.call(server, :renew)

  @doc "The user's answer to a `{:mob_pair_request, server, ref, request}`."
  @spec decide(GenServer.server(), reference(), :allow | :deny) :: :ok
  def decide(server, ref, decision) when decision in [:allow, :deny],
    do: GenServer.call(server, {:decide, ref, decision})

  @impl true
  def init(opts) do
    cert = Keyword.fetch!(opts, :cert)
    host = Keyword.get_lazy(opts, :host, &default_host/0)
    dist_proto = Keyword.get(opts, :dist_proto, :inet_tls)

    _ = Keyword.fetch!(opts, :service)

    case Keyword.get(opts, :dist_host) do
      plain when dist_proto == :inet_tcp and is_binary(plain) ->
        if Record.loopback?(plain),
          do: start(opts, cert, host),
          else: {:stop, :plain_distribution_off_loopback}

      _ when dist_proto in [:inet_tcp, :inet_tls] ->
        loopback_dist(opts, cert, host)

      _ ->
        {:stop, {:bad_option, :dist_proto}}
    end
  end

  defp loopback_dist(opts, cert, host) do
    case Map.new(Keyword.get(opts, :loopback_dist, [])) do
      %{proto: proto} when proto not in [:inet_tcp, :inet_tls] ->
        {:stop, {:bad_option, :loopback_dist}}

      %{port: port} when not is_integer(port) or port not in 1..65_535 ->
        {:stop, {:bad_option, :loopback_dist}}

      _ ->
        start(opts, cert, host)
    end
  end

  defp start(opts, cert, host) do
    {:ok, _} = Application.ensure_all_started(:ssl)

    listen_options =
      [
        certs_keys: [Cert.ssl_cert_key(cert.cert, cert.key)],
        ip: Keyword.get(opts, :ip, {0, 0, 0, 0}),
        reuseaddr: true
      ] ++ Wire.socket_options()

    {:ok, listen} = :ssl.listen(Keyword.get(opts, :port, 0), listen_options)
    {:ok, {_, port}} = :ssl.sockname(listen)
    server = self()
    acceptor = spawn_link(fn -> accept_loop(server, listen) end)

    service = Keyword.fetch!(opts, :service)
    inst = Keyword.get(opts, :inst, "a")
    dist_port = Keyword.fetch!(opts, :dist_port)
    dist_proto = Keyword.get(opts, :dist_proto, :inet_tls)
    loopback = Map.new(Keyword.get(opts, :loopback_dist, []))

    config = %{
      service: service,
      cert: cert,
      inst: inst,
      name: Keyword.get(opts, :name, String.capitalize(service) <> " " <> String.upcase(inst)),
      device: Keyword.get_lazy(opts, :device, &hostname/0),
      firmware: Keyword.get(opts, :firmware),
      node: Keyword.get_lazy(opts, :node, fn -> Atom.to_string(node()) end),
      host: host,
      port: port,
      dist_host: Keyword.get(opts, :dist_host, host),
      dist_port: dist_port,
      dist_proto: dist_proto,
      loopback_port: Map.get(loopback, :port, dist_port),
      loopback_proto: Map.get(loopback, :proto, dist_proto),
      approve: Keyword.get(opts, :approve, fn _request -> :deny end),
      pairings: Keyword.get(opts, :pairings, MobPair.Pairings)
    }

    state = %{
      config: config,
      listen: listen,
      acceptor: acceptor,
      ttl: Keyword.get(opts, :ttl, @ttl),
      max_attempts: Keyword.get(opts, :max_attempts, @max_attempts),
      secret: nil,
      notify: Keyword.get(opts, :notify),
      asks: %{},
      handshakes: %{},
      responder: nil
    }

    state = %{state | secret: new_secret(state)}
    {:ok, advertise(state, Keyword.get(opts, :advertise, false))}
  end

  @impl true
  def handle_call(:code, _from, state), do: {:reply, Code.format(state.secret.code), state}

  def handle_call(:link, _from, state), do: {:reply, build_link(state), state}

  def handle_call(:info, _from, %{secret: secret} = state) do
    left = max(secret.expires_at - System.monotonic_time(:millisecond), 0)

    info = %{
      code: Code.format(secret.code),
      link: build_link(state),
      port: state.config.port,
      status: if(secret.status == :open and left == 0, do: :expired, else: secret.status),
      attempts_left: max(state.max_attempts - secret.attempts, 0),
      expires_in: left,
      advertising: state.responder != nil
    }

    {:reply, info, state}
  end

  def handle_call(:port, _from, state), do: {:reply, state.config.port, state}
  def handle_call(:responder, _from, state), do: {:reply, state.responder, state}
  def handle_call(:renew, _from, state), do: {:reply, :ok, renew_secret(state)}
  def handle_call(:config, _from, state), do: {:reply, state.config, state}

  def handle_call({:check_token, token}, _from, state) do
    case usable(state) do
      :ok ->
        if Srp.same?(token, state.secret.token),
          do: {:reply, :ok, consume(state)},
          else: failed(state, "invalid_token")

      error ->
        {:reply, error, state}
    end
  end

  # The verifier (a 2048-bit modpow) is computed by the connection, not here.
  def handle_call(:srp_code, _from, state) do
    case usable(state) do
      :ok ->
        {:reply, {:ok, state.secret.code}, state}

      error ->
        {:reply, error, state}
    end
  end

  def handle_call({:srp_result, proof_ok?}, _from, state) do
    case usable(state) do
      :ok -> if proof_ok?, do: {:reply, :ok, consume(state)}, else: failed(state, "wrong_code")
      error -> {:reply, error, state}
    end
  end

  def handle_call({:admit, handler}, _from, state) do
    if map_size(state.handshakes) < @max_handshakes,
      do: {:reply, :ok, put_in(state.handshakes[Process.monitor(handler)], handler)},
      else: {:reply, :busy, state}
  end

  def handle_call({:ask, request}, {handler, _}, %{config: %{approve: {:ask, pid}}} = state) do
    ref = make_ref()
    send(pid, {:mob_pair_request, self(), ref, request})
    {:reply, {:ok, ref}, put_in(state.asks[ref], handler)}
  end

  def handle_call({:decide, ref, decision}, _from, state) do
    {handler, asks} = Map.pop(state.asks, ref)
    if handler, do: send(handler, {:decision, ref, decision})
    {:reply, :ok, %{state | asks: asks}}
  end

  def handle_call({:withdraw, ref}, _from, %{config: %{approve: {:ask, pid}}} = state) do
    {handler, asks} = Map.pop(state.asks, ref)
    if handler, do: send(pid, {:mob_pair_withdrawn, self(), ref})
    {:reply, :ok, %{state | asks: asks}}
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state),
    do: {:noreply, %{state | handshakes: Map.delete(state.handshakes, ref)}}

  # A responder that failed to start (see start_responder/1).
  def handle_info({:EXIT, _pid, _reason}, state), do: {:noreply, state}

  # The code and token stay out of crash reports and :sys.get_status/1.
  @impl true
  def format_status(status) do
    Map.update(status, :state, nil, fn
      %{secret: %{} = secret} = state ->
        %{state | secret: %{secret | code: :redacted, token: :redacted}}

      other ->
        other
    end)
  end

  @impl true
  def terminate(_reason, state) do
    :ssl.close(state.listen)
    if state.responder, do: Responder.stop(state.responder)
  end

  defp build_link(%{config: c} = state) do
    Link.build(%{
      service: c.service,
      inst: c.inst,
      node: short_name(c.node),
      host: c.host,
      port: c.port,
      fp: c.cert.fp,
      token: state.secret.token
    })
  end

  defp renew_secret(state), do: changed(%{state | secret: new_secret(state)})

  # The secret: usable while open and unexpired.
  defp new_secret(state) do
    %{
      code: Code.generate(),
      token: :crypto.strong_rand_bytes(16),
      expires_at: System.monotonic_time(:millisecond) + state.ttl,
      attempts: 0,
      status: :open
    }
  end

  defp changed(%{notify: nil} = state), do: state

  defp changed(state) do
    send(state.notify, {:mob_pair_secret, self(), state.secret.status})
    state
  end

  defp usable(%{secret: %{status: :invalid}}), do: {:error, "too_many_attempts"}
  defp usable(%{secret: %{status: :used}}), do: {:error, "expired"}

  defp usable(%{secret: secret}) do
    if System.monotonic_time(:millisecond) < secret.expires_at, do: :ok, else: {:error, "expired"}
  end

  defp consume(state), do: changed(put_in(state.secret.status, :used))

  defp failed(state, reason) do
    attempts = state.secret.attempts + 1
    left = state.max_attempts - attempts

    secret = %{
      state.secret
      | attempts: attempts,
        status: if(left <= 0, do: :invalid, else: :open)
    }

    reply =
      cond do
        left <= 0 -> {:error, "too_many_attempts"}
        reason == "wrong_code" -> {:error, "wrong_code", left}
        true -> {:error, reason}
      end

    {:reply, reply, changed(%{state | secret: secret})}
  end

  defp advertise(state, false), do: state

  defp advertise(%{config: c} = state, opts) do
    txt =
      %{
        "v" => "1",
        "inst" => c.inst,
        "node" => c.node,
        "fp" => Wire.b64(c.cert.fp),
        "port" => Integer.to_string(c.port),
        "dport" => Integer.to_string(c.dist_port),
        "fw" => c.firmware,
        "dev" => c.device
      }
      |> Map.reject(fn {_k, v} -> is_nil(v) end)

    with {:ok, address} <- :inet.parse_strict_address(String.to_charlist(c.host)),
         {:ok, responder} <-
           [
             service: c.service,
             instance: c.name,
             hostname: "#{c.service}-#{c.inst}.local",
             address: address,
             srv_port: c.port,
             txt: txt
           ]
           |> Keyword.merge(opts)
           |> start_responder() do
      %{state | responder: responder}
    else
      {:error, reason} ->
        Logger.warning("MobPair.Host: not advertising over mDNS: #{inspect(reason)}")
        state
    end
  end

  # The responder links to the server; a failed start must not take it down.
  defp start_responder(opts) do
    trap? = Process.flag(:trap_exit, true)

    try do
      Responder.start_link(opts)
    catch
      :exit, reason -> {:error, reason}
    after
      Process.flag(:trap_exit, trap?)
    end
  end

  defp accept_loop(server, listen) do
    case :ssl.transport_accept(listen) do
      {:ok, socket} ->
        handler =
          spawn(fn ->
            receive do
              :go -> handle_connection(server, socket)
            end
          end)

        case :ssl.controlling_process(socket, handler) do
          :ok -> send(handler, :go)
          {:error, _} -> Process.exit(handler, :kill)
        end

        accept_loop(server, listen)

      {:error, :closed} ->
        :ok

      {:error, _} ->
        accept_loop(server, listen)
    end
  end

  # One sibling's exchange, in its own process; at most @max_handshakes at a
  # time, so a peer on the Wi-Fi can't exhaust processes or CPU.
  defp handle_connection(server, transport_socket) do
    with :ok <- admit(server, transport_socket),
         {:ok, socket} <- :ssl.handshake(transport_socket, @step_timeout) do
      config = GenServer.call(server, :config)

      case exchange(server, socket, config) do
        :ok -> :ok
        {:error, message} -> Wire.send(socket, message)
      end

      :ssl.close(socket)
    end
  end

  defp admit(server, transport_socket) do
    case GenServer.call(server, {:admit, self()}) do
      :ok ->
        :ok

      :busy ->
        :ssl.close(transport_socket)
        :busy
    end
  end

  defp exchange(server, socket, config) do
    with {:ok, hello} <- recv(socket),
         :ok <- check_hello(hello, config),
         :ok <- check_carrier(socket, config),
         :ok <- authenticate(server, socket, config, hello),
         {:ok, request} <- recv_request(socket, config),
         {:ok, request} <- describe(socket, request),
         :ok <- Wire.send(socket, %{"type" => "pending"}),
         :allow <- decide(server, socket, config, request) do
      grant(socket, config, request)
    else
      :deny -> {:error, Wire.error("denied")}
      {:error, %{"type" => "error"}} = error -> error
      {:error, :timeout} -> {:error, Wire.error("timeout")}
      {:error, _closed_or_bad} -> {:error, Wire.error("bad_message")}
    end
  end

  defp check_hello(%{"type" => "hello", "v" => 1, "inst" => inst}, %{inst: inst}), do: :ok

  defp check_hello(%{"type" => "hello", "v" => 1}, _config),
    do: {:error, Wire.error("no_such_instance")}

  defp check_hello(%{"type" => "hello"}, _config), do: {:error, Wire.error("unsupported_version")}
  defp check_hello(_message, _config), do: {:error, Wire.error("bad_message")}

  # Plain distribution only reaches loopback (protocol §2): a host without
  # TLS distribution pairs only siblings on the same phone, and refuses others
  # before they spend an attempt.
  defp check_carrier(socket, %{dist_proto: :inet_tcp}) do
    if loopback_peer?(socket), do: :ok, else: {:error, Wire.error("loopback_only")}
  end

  defp check_carrier(_socket, %{dist_proto: :inet_tls}), do: :ok

  defp loopback_peer?(socket), do: match?({:ok, {{127, _, _, _}, _}}, :ssl.peername(socket))

  defp authenticate(server, socket, _config, %{"auth" => "token", "token" => token}) do
    with {:ok, token} <- decode(token, size: 16),
         :ok <- secret_call(server, {:check_token, token}) do
      Wire.send(socket, %{"type" => "welcome"})
    end
  end

  defp authenticate(server, socket, config, %{"auth" => "srp", "A" => a}) do
    with {:ok, a_pub} <- decode(a, max: 256),
         true <- Srp.valid_public?(a_pub) || {:error, Wire.error("bad_message")},
         {:ok, code} <- secret_call(server, :srp_code),
         salt = Srp.salt(),
         verifier = Srp.verifier(code, salt, config.service),
         {b_pub, _} = keys = Srp.server_keys(verifier),
         :ok <-
           Wire.send(socket, %{
             "type" => "challenge",
             "salt" => Wire.b64(salt),
             "B" => Wire.b64(b_pub)
           }),
         {:ok, %{"type" => "proof", "M1" => m1}} <- recv(socket),
         {:ok, m1} <- decode(m1, size: 32),
         {:ok, key} <- Srp.server_key(verifier, a_pub, keys),
         {:ok, binding} <- Wire.channel_binding(socket),
         expected = Srp.client_proof(key, config.cert.fp, binding, a_pub, b_pub, config.service),
         :ok <- secret_call(server, {:srp_result, Srp.same?(m1, expected)}) do
      m2 = Srp.server_proof(key, config.cert.fp, binding, a_pub, b_pub, m1, config.service)
      Wire.send(socket, %{"type" => "welcome", "M2" => Wire.b64(m2)})
    else
      {:error, _} = error -> error
      _ -> {:error, Wire.error("bad_message")}
    end
  end

  defp authenticate(_server, _socket, _config, _hello), do: {:error, Wire.error("bad_message")}

  defp secret_call(server, request) do
    case GenServer.call(server, request) do
      {:error, "wrong_code", left} ->
        {:error, Wire.error("wrong_code", %{"attempts_left" => left})}

      {:error, reason} ->
        {:error, Wire.error(reason)}

      other ->
        other
    end
  end

  defp recv_request(socket, config) do
    with {:ok, %{"type" => "request"} = m} <- recv(socket),
         {:ok, app_id} <- text(m["app_id"], 1, 200),
         {:ok, app_name} <- text(m["app_name"], 1, 100),
         {:ok, device_name} <- text(m["device_name"], 0, 100),
         true <- Record.self_node?(m["node"]),
         :ok <- sibling_node(m["node"], config),
         {:ok, cert} <- decode(m["client_cert"], max: 4096) do
      client_fp = Cert.fingerprint(cert)

      {:ok,
       %{
         app_id: app_id,
         app_name: app_name,
         device_name: device_name,
         node: m["node"],
         client_fp: client_fp,
         replaces: replaces(config.pairings, m["node"], client_fp)
       }}
    else
      {:error, _} = error -> error
      _ -> {:error, Wire.error("bad_message")}
    end
  end

  # A sibling can't take the host's own name (its cookie would become the
  # host's default cookie) or any instance's of the host's service.
  defp sibling_node(node, config) do
    if node == config.node or String.starts_with?(node, config.service <> "_"),
      do: {:error, Wire.error("bad_node")},
      else: :ok
  end

  # Another app already paired under this node name with another
  # certificate: the Allow sheet must say it would be replaced.
  defp replaces(pairings, node, client_fp) do
    case pairings.get(node) do
      %{client_fp: ^client_fp} -> nil
      %{} = old -> Map.take(old, [:app_name, :device_name, :paired_at])
      nil -> nil
    end
  end

  defp describe(socket, request) do
    {:ok, {ip, _}} = :ssl.peername(socket)
    {:ok, Map.put(request, :remote_ip, ip)}
  end

  defp decide(_server, _socket, %{approve: fun}, request) when is_function(fun, 1),
    do: fun.(request)

  defp decide(server, socket, %{approve: {:ask, _pid}}, request) do
    {:ok, ref} = GenServer.call(server, {:ask, request})
    :ok = :ssl.setopts(socket, active: :once)

    receive do
      {:decision, ^ref, decision} ->
        decision

      {closed, ^socket} when closed in [:ssl_closed, :ssl_error] ->
        GenServer.call(server, {:withdraw, ref})
        {:error, :closed}
    after
      @decision_timeout ->
        GenServer.call(server, {:withdraw, ref})
        {:error, :timeout}
    end
  end

  defp grant(socket, config, request) do
    loopback? = match?({127, _, _, _}, request.remote_ip)

    # Plain distribution only on loopback; check_carrier/2 already turned a
    # remote sibling away when TLS distribution is off.
    {host, port, proto} =
      if loopback?,
        do: {"127.0.0.1", config.loopback_port, config.loopback_proto},
        else: {config.dist_host, config.dist_port, :inet_tls}

    {:ok, pairing} =
      request
      |> Map.take([:node, :app_id, :app_name, :device_name, :client_fp])
      |> Map.put(:dist_proto, proto)
      |> config.pairings.add()

    Wire.send(socket, %{
      "type" => "granted",
      "inst" => config.inst,
      "name" => config.name,
      "device" => config.device,
      "firmware" => config.firmware,
      "node" => config.node,
      "dist_host" => host,
      "dist_port" => port,
      "dist_proto" => Atom.to_string(proto),
      "cookie" => pairing.cookie
    })
  end

  defp recv(socket) do
    case Wire.recv(socket, @step_timeout) do
      {:ok, %{"type" => "error"}} -> {:error, :closed}
      other -> other
    end
  end

  defp decode(value, opts) do
    case Wire.unb64(value, opts) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, Wire.error("bad_message")}
    end
  end

  # Text for the Allow sheet: control and format characters (newlines, bidi
  # overrides) removed, then the length checked.
  defp text(value, min, max) when is_binary(value) do
    with true <- String.valid?(value),
         clean = String.replace(value, ~r/[\p{Cc}\p{Cf}]/u, ""),
         true <- String.length(clean) in min..max do
      {:ok, clean}
    else
      _ -> :error
    end
  end

  defp text(_value, _min, _max), do: :error

  defp short_name(node), do: node |> String.split("@") |> hd()

  defp default_host do
    {:ok, addresses} = :inet.getifaddrs()

    addresses
    |> Enum.flat_map(fn {_name, opts} -> Keyword.get_values(opts, :addr) end)
    |> Enum.find(&match?({a, _, _, _} when a != 127, &1))
    |> case do
      nil -> "127.0.0.1"
      ip -> ip |> :inet.ntoa() |> List.to_string()
    end
  end

  defp hostname do
    {:ok, name} = :inet.gethostname()
    List.to_string(name)
  end
end
