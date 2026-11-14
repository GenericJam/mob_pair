defmodule MobPair.Responder do
  @moduledoc """
  A DNS-SD responder for a host app: advertises one instance of
  `_<service>._tcp.local` over multicast DNS. It is the advertising half of
  the discovery protocol written as code; `MobPair.Discovery`
  is the browsing half.

  On Android FMutate advertises with `NsdManager` (the system responder
  owns port 5353) using the same instance name, service type and TXT keys.
  This module is for tests, for hosts standing in for FMutate (a Mac) and
  as the specification.

  ## What is advertised

    * PTR `_fmutate._tcp.local` → `<instance>._fmutate._tcp.local`
      (instance `FMutate A`; a DNS-SD responder may suffix ` (2)` on a
      name conflict; this one does not probe)
    * SRV `<instance>._fmutate._tcp.local` → `:hostname`, `:srv_port`
    * TXT `<instance>._fmutate._tcp.local` with the keys
      `v=1`, `inst` (instance id, `a`), `node` (FMutate's full node name,
      `fmutate_a@192.168.1.23`), `fp` (sha256 of FMutate's TLS certificate,
      base64url without padding), `port` (the pairing port, only while
      pairing is open), `dport` (the distribution port), `fw` (firmware
      name, `X0X`), `dev` (device name, `Pixel 7`)
    * A `:hostname` → `:address`

  A PTR query for the service, or an SRV, TXT, A or ANY query for one of
  its own names, gets all four records: the matching ones as answers, the
  rest as additionals. Responses and queries for other names are ignored.

  ## How it replies (RFC 6762)

  Queries from addresses outside the served subnet are ignored (§11): the
  `:interface`'s subnet when given, else every directly attached IPv4
  subnet; loopback (this host) always counts.

    * Query from a port other than 5353 (legacy unicast, §6.7): unicast to
      the query's source address and port, echoing the query id and
      questions, TTL 10, no cache-flush bits.
    * Query with the QU bit (§5.4): unicast to the source, id 0, TTL 120.
    * Otherwise: multicast to `224.0.0.251:5353` on the `:interface` (else
      every IPv4 interface), TTL 120.

  SRV, TXT and A are unique records (cache-flush bit set in multicast
  replies); PTR is shared.

  ## Load

  The socket hands over one datagram at a time (`active: :once`), so a
  flood waits in the kernel's bounded socket buffer (and is dropped there),
  never in the mailbox. At most `:max_packets` datagrams are read and
  `:max_replies` replies sent per second; past either, the rest of the
  second's datagrams are left unread or unanswered.

  ## Options

    * `:instance` – instance label, e.g. `"FMutate A"` (required)
    * `:hostname` – e.g. `"fmutate-a.local"` (required)
    * `:address` – IPv4 tuple for the A record (required)
    * `:srv_port` – SRV port (required)
    * `:txt` – map of TXT keys to values (default `%{}`)
    * `:service` – the host app's service name, e.g. `"fmutate"` (required)
    * `:interface` – the IPv4 address of the one interface to serve (the
      Wi-Fi address; `MobPair.Host` passes its link's address): the group
      is joined and multicast replies sent only there, and only its subnet
      is on-link. A start fails with `{:no_interface, ip}` when no local
      interface has it. Default nil: every interface.
    * `:bind` – `{ip, port}`, default `{{0, 0, 0, 0}, 5353}`. When bound to
      `0.0.0.0` the socket sets `reuseaddr` and `reuseport` (to share 5353
      with the system responder) and joins `224.0.0.251` on the
      `:interface` (else every up IPv4 interface). Tests bind
      `{{127, 0, 0, 1}, 0}`.
    * `:max_packets` – datagrams read per second (default 200)
    * `:max_replies` – replies sent per second (default 20)
    * `:name` – GenServer name
  """

  use GenServer

  alias MobPair.Dns

  @mdns_group {224, 0, 0, 251}
  @mdns_port 5353
  @ttl 120
  @legacy_ttl 10
  @max_packets 200
  @max_replies 20
  @window 1_000

  @doc "Starts the responder linked to the caller; see the moduledoc for options."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name)
    GenServer.start_link(__MODULE__, opts, if(name, do: [name: name], else: []))
  end

  @doc "The UDP port the responder is bound to."
  @spec port(GenServer.server()) :: :inet.port_number()
  def port(server), do: GenServer.call(server, :port)

  @doc "Replaces the TXT key/value map (e.g. adding `port` when pairing opens)."
  @spec update_txt(GenServer.server(), %{String.t() => String.t()}) :: :ok
  def update_txt(server, txt), do: GenServer.call(server, {:update_txt, txt})

  @doc "Stops the responder."
  @spec stop(GenServer.server()) :: :ok
  def stop(server), do: GenServer.stop(server)

  @impl true
  def init(opts) do
    service = Dns.name("_#{Keyword.fetch!(opts, :service)}._tcp.local")
    {ip, port} = Keyword.get(opts, :bind, {{0, 0, 0, 0}, @mdns_port})
    any? = ip == {0, 0, 0, 0}

    with {:ok, served} <- served(Keyword.get(opts, :interface)),
         interfaces = if(any?, do: multicast_interfaces(served), else: []),
         {:ok, socket} <- :gen_udp.open(port, socket_opts(ip, any?)),
         :ok <- join(socket, interfaces) do
      {:ok,
       %{
         socket: socket,
         interfaces: interfaces,
         subnets: Enum.map(served, fn {_name, addr, mask} -> {mask_ip(addr, mask), mask} end),
         service: service,
         instance: [Keyword.fetch!(opts, :instance) | service],
         hostname: opts |> Keyword.fetch!(:hostname) |> Dns.name(),
         address: Keyword.fetch!(opts, :address),
         srv_port: Keyword.fetch!(opts, :srv_port),
         txt: Keyword.get(opts, :txt, %{}),
         max_packets: Keyword.get(opts, :max_packets, @max_packets),
         max_replies: Keyword.get(opts, :max_replies, @max_replies),
         window: new_window()
       }}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  defp socket_opts(ip, true) do
    [:binary, active: :once, ip: ip, reuseaddr: true, reuseport: true] ++
      [multicast_loop: true, multicast_ttl: 255]
  end

  defp socket_opts(ip, false), do: [:binary, active: :once, ip: ip]

  defp join(socket, interfaces) do
    Enum.reduce_while(interfaces, :ok, fn address, :ok ->
      case :inet.setopts(socket, add_membership: {@mdns_group, address}) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  # The served IPv4 addresses `{interface_flags, address, netmask}`: the one
  # `interface` (it must be local), or every one.
  defp served(interface) do
    addresses =
      case :inet.getifaddrs() do
        {:ok, interfaces} ->
          for {_name, opts} <- interfaces,
              {{_, _, _, _} = addr, {_, _, _, _} = mask} <- pairs(opts),
              do: {Keyword.get(opts, :flags, []), addr, mask}

        {:error, _reason} ->
          []
      end

    case interface do
      nil ->
        {:ok, addresses}

      ip ->
        case Enum.filter(addresses, &match?({_, ^ip, _}, &1)) do
          [] -> {:error, {:no_interface, ip}}
          mine -> {:ok, mine}
        end
    end
  end

  # getifaddrs lists each address followed by its netmask.
  defp pairs([{:addr, addr}, {:netmask, mask} | rest]), do: [{addr, mask} | pairs(rest)]
  defp pairs([_ | rest]), do: pairs(rest)
  defp pairs([]), do: []

  # RFC 6762 §11: answer only queries from this host or a served subnet,
  # never a querier further away.
  defp on_link?(_subnets, {127, _, _, _}), do: true

  defp on_link?(subnets, {_, _, _, _} = ip),
    do: Enum.any?(subnets, fn {net, mask} -> mask_ip(ip, mask) == net end)

  defp on_link?(_subnets, _ip), do: false

  defp mask_ip({a, b, c, d}, {w, x, y, z}),
    do: {Bitwise.band(a, w), Bitwise.band(b, x), Bitwise.band(c, y), Bitwise.band(d, z)}

  defp multicast_interfaces(served) do
    for {flags, address, _mask} <- served,
        :up in flags,
        :multicast in flags,
        uniq: true,
        do: address
  end

  @impl true
  def handle_call(:port, _from, state) do
    {:ok, port} = :inet.port(state.socket)
    {:reply, port, state}
  end

  def handle_call({:update_txt, txt}, _from, state), do: {:reply, :ok, %{state | txt: txt}}

  # One datagram at a time; the socket is re-armed after it, unless this
  # second's budget is spent (then at the next second).
  @impl true
  def handle_info({:udp, socket, ip, port, data}, %{socket: socket} = state) do
    state = state |> tick() |> count(:packets)

    state =
      with true <- on_link?(state.subnets, ip),
           {:ok, query} <- Dns.decode(data),
           false <- Dns.response?(query),
           [_ | _] = questions <- Enum.filter(query.questions, &ours?(state, &1)),
           true <- state.window.replies < state.max_replies do
        reply(state, query, questions, ip, port)
        count(state, :replies)
      else
        _ -> state
      end

    {:noreply, rearm(state)}
  end

  def handle_info(:rearm, state), do: {:noreply, state |> tick() |> rearm()}

  def handle_info(_message, state), do: {:noreply, state}

  defp new_window,
    do: %{ends: System.monotonic_time(:millisecond) + @window, packets: 0, replies: 0}

  defp tick(state) do
    if System.monotonic_time(:millisecond) >= state.window.ends,
      do: %{state | window: new_window()},
      else: state
  end

  defp count(state, key), do: update_in(state.window[key], &(&1 + 1))

  # Read one more datagram, or wait for the next second's budget.
  defp rearm(state) do
    if state.window.packets < state.max_packets do
      :ok = :inet.setopts(state.socket, active: :once)
      state
    else
      wait = max(state.window.ends - System.monotonic_time(:millisecond), 0)
      Process.send_after(self(), :rearm, wait)
      state
    end
  end

  defp ours?(state, %{name: name, type: type}) do
    key = Dns.name_key(name)

    cond do
      key == Dns.name_key(state.service) -> type in [:ptr, :any]
      key == Dns.name_key(state.instance) -> type in [:srv, :txt, :any]
      key == Dns.name_key(state.hostname) -> type in [:a, :any]
      true -> false
    end
  end

  defp reply(state, query, questions, ip, port) when port != @mdns_port do
    {answers, additionals} = records(state, questions, @legacy_ttl, false)

    packet =
      Dns.encode_response(%{
        id: query.id,
        questions: query.questions,
        answers: answers,
        additionals: additionals
      })

    :gen_udp.send(state.socket, ip, port, packet)
  end

  defp reply(state, _query, questions, ip, port) do
    {answers, additionals} = records(state, questions, @ttl, true)
    packet = Dns.encode_response(%{answers: answers, additionals: additionals})

    if Enum.any?(questions, & &1.qu) or state.interfaces == [] do
      :gen_udp.send(state.socket, ip, port, packet)
    else
      Enum.each(state.interfaces, fn address ->
        :inet.setopts(state.socket, multicast_if: address)
        :gen_udp.send(state.socket, @mdns_group, @mdns_port, packet)
      end)
    end
  end

  defp records(state, questions, ttl, flush) do
    all = [
      %{name: state.service, type: :ptr, ttl: ttl, cache_flush: false, data: state.instance},
      %{
        name: state.instance,
        type: :srv,
        ttl: ttl,
        cache_flush: flush,
        data: %{priority: 0, weight: 0, port: state.srv_port, target: state.hostname}
      },
      %{
        name: state.instance,
        type: :txt,
        ttl: ttl,
        cache_flush: flush,
        data: Dns.txt_strings(state.txt)
      },
      %{name: state.hostname, type: :a, ttl: ttl, cache_flush: flush, data: state.address}
    ]

    Enum.split_with(all, fn record ->
      Enum.any?(questions, fn question ->
        Dns.name_key(question.name) == Dns.name_key(record.name) and
          question.type in [record.type, :any]
      end)
    end)
  end
end
