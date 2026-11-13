defmodule MobPair.Discovery do
  @moduledoc """
  Finds host app instances (FMutate, Magpie…) on the local network: a
  one-shot DNS-SD browse for `_<service>._tcp.local` over multicast DNS.

  ## Why one-shot legacy unicast

  The query goes out as an RFC 6762 §5.1 *one-shot* query from an ephemeral
  UDP port, not 5353. A compliant responder (Android's mdnsd behind
  `NsdManager`, macOS mDNSResponder, `MobPair.Responder`)
  treats a query from a port other than 5353 as a *legacy unicast* query
  (§6.7) and answers by unicast straight to the sending socket, echoing the
  query id. Humdinger therefore never receives multicast: on Android it
  needs no `WifiManager.MulticastLock` and does not share port 5353 with the
  system responder. Sending multicast needs neither.

  By default one socket is opened per up, non-loopback, multicast-capable
  IPv4 interface, bound to that interface's address, with `multicast_if`
  set to it and a multicast TTL of 255; the query goes to
  `224.0.0.251:5353` on each. It is sent at 0, 250 and 750 ms (those before
  the timeout) to survive packet loss. When a PTR answer arrives without
  the instance's SRV or TXT record, or an SRV without the A record of its
  target, the missing records are asked for at once (macOS includes them
  as additionals; Android's mdnsd may not).

  ## Candidates

  The TXT keys FMutate advertises:

    * `v` – `1` (instances with another version are dropped; missing means 1)
    * `inst` – instance id, e.g. `a` (required)
    * `node` – FMutate's full node name, e.g. `fmutate_a@192.168.1.23`
      (required)
    * `fp` – sha256 of FMutate's TLS certificate, base64url without padding
      (required; decoded to 32 bytes)
    * `port` – the pairing port, present only while FMutate's Pair screen is
      open
    * `dport` – the distribution port
    * `fw` – firmware name, e.g. `X0X`
    * `dev` – device name, e.g. `Pixel 7`

  The instance name is the DNS-SD instance label (`FMutate A`, possibly
  suffixed ` (2)` by the responder). `host` is the A record of the SRV
  target, or the source address of the reply when that is missing.

  ## Spoofed answers

  mDNS is unauthenticated: anyone on the LAN can answer with FMutate's
  instance label, `fp` and `inst`. So nothing one responder says can change
  what another said: a reply is only taken when its id is one of the
  queries' ids, and the PTR, SRV, TXT and A records are kept per instance
  *and* per reply source (`{ip, port}`). SRV and TXT records count only from
  the source whose PTR named the instance, and A records only for that
  source's SRV targets. A forged reply under FMutate's label therefore
  becomes a second candidate next to the genuine one, never a replacement;
  `MobPair.Join` tries candidates and keeps the one whose TLS
  fingerprint and cookie handshake succeed.

  Candidates are deduplicated by `{fp, inst, host, dist_port}` (the latest
  answer wins; anything that changes where Humdinger would connect is a
  separate candidate) and ordered by name. Every string is the binary from
  the packet; no atoms are created from network data. Malformed packets are
  ignored (see `MobPair.Dns`).
  """

  alias MobPair.Dns

  @mdns {{224, 0, 0, 251}, 5353}
  @timeout 1_500
  @resends [0, 250, 750]
  @recv_max 9000
  @max_instances 64

  @type candidate :: %{
          name: String.t(),
          inst: String.t(),
          node: String.t(),
          host: String.t(),
          port: :inet.port_number() | nil,
          dist_port: :inet.port_number() | nil,
          fp: <<_::256>>,
          firmware: String.t() | nil,
          device: String.t() | nil
        }

  @type target :: {:inet.ip4_address(), :inet.port_number()}

  @doc """
  Browses for instances of `:service` for `:timeout` ms (default 1500) and returns
  what answered.

  Options:

    * `:service` – the host app's service name, e.g. `"fmutate"` (required)
    * `:timeout` – how long to collect replies, in ms
    * `:targets` – `[{ip, port}]` to query instead of the mDNS group on every
      interface, sent from one socket bound to loopback (when every target is
      loopback) or to `0.0.0.0`

  Returns `{:error, :no_interface}` when no IPv4 multicast interface is up,
  or the socket error when no socket could be opened.
  """
  @spec browse(keyword()) :: {:ok, [candidate()]} | {:error, term()}
  def browse(opts) do
    timeout = Keyword.get(opts, :timeout, @timeout)
    service = Dns.name("_#{Keyword.fetch!(opts, :service)}._tcp.local")

    with {:ok, sockets} <- open_sockets(Keyword.get(opts, :targets)) do
      now = now()
      id = query_id()

      state = %{
        sockets: Map.new(sockets),
        service: service,
        service_key: Dns.name_key(service),
        deadline: now + timeout,
        resends: Enum.map(Enum.filter(@resends, &(&1 < timeout)), &(&1 + now)),
        query: Dns.encode_query([%{name: service, type: :ptr}], id),
        ids: MapSet.new([id]),
        seq: 0,
        instances: %{},
        a: %{},
        asked: MapSet.new()
      }

      candidates = state |> collect() |> candidates()
      Enum.each(sockets, fn {socket, _targets} -> close(socket) end)
      {:ok, candidates}
    end
  end

  defp open_sockets(nil) do
    case interface_addresses() do
      [] ->
        {:error, :no_interface}

      addresses ->
        opened =
          for address <- addresses,
              {:ok, socket} <- [open(address, multicast_if: address)],
              do: {socket, [@mdns]}

        if opened == [], do: {:error, :no_socket}, else: {:ok, opened}
    end
  end

  defp open_sockets(targets) do
    bind =
      if Enum.all?(targets, fn {ip, _port} -> elem(ip, 0) == 127 end),
        do: {127, 0, 0, 1},
        else: {0, 0, 0, 0}

    with {:ok, socket} <- open(bind, []), do: {:ok, [{socket, targets}]}
  end

  defp open(address, extra) do
    :gen_udp.open(
      0,
      [:binary, active: true, ip: address, multicast_ttl: 255, recbuf: 65_536] ++ extra
    )
  end

  defp close(socket) do
    :gen_udp.close(socket)
    flush(socket)
  end

  defp flush(socket) do
    receive do
      {:udp, ^socket, _ip, _port, _data} -> flush(socket)
    after
      0 -> :ok
    end
  end

  defp interface_addresses do
    case :inet.getifaddrs() do
      {:ok, interfaces} ->
        for {_name, opts} <- interfaces,
            flags = Keyword.get(opts, :flags, []),
            :up in flags and :multicast in flags and :loopback not in flags,
            {:addr, {_, _, _, _} = address} <- opts,
            elem(address, 0) != 127,
            uniq: true,
            do: address

      {:error, _reason} ->
        []
    end
  end

  defp collect(state) do
    now = now()

    case state.resends do
      [at | rest] when at <= now ->
        send_all(state, state.query)
        collect(%{state | resends: rest})

      resends ->
        wake = Enum.min([state.deadline | resends])
        wait = max(wake - now, 0)

        if now >= state.deadline, do: state, else: receive_reply(state, wait)
    end
  end

  defp receive_reply(state, wait) do
    sockets = state.sockets

    receive do
      {:udp, socket, ip, port, data} when is_map_key(sockets, socket) ->
        state |> handle_reply(socket, {ip, port}, data) |> collect()
    after
      wait -> collect(state)
    end
  end

  defp send_all(state, packet) do
    Enum.each(state.sockets, fn {socket, targets} -> send_to(socket, targets, packet) end)
  end

  defp send_to(socket, targets, packet) do
    Enum.each(targets, fn {ip, port} -> :gen_udp.send(socket, ip, port, packet) end)
  end

  defp handle_reply(state, _socket, _source, data) when byte_size(data) > @recv_max, do: state

  # A legacy unicast reply echoes its query's id; anything else wasn't asked
  # for. Everything a reply says is filed under its source, so one responder
  # can't overwrite another's records.
  defp handle_reply(state, socket, source, data) do
    with {:ok, message} <- Dns.decode(data),
         true <- Dns.response?(message),
         true <- MapSet.member?(state.ids, message.id) do
      records = message.answers ++ message.additionals
      state = %{state | seq: state.seq + 1}

      state
      |> take_ptrs(records, source)
      |> take_instance_records(records, source)
      |> take_addresses(records, source)
      |> follow_up(socket)
    else
      _ -> state
    end
  end

  defp take_ptrs(state, records, source) do
    Enum.reduce(records, state, fn
      %{type: :ptr, name: name, data: [_label | rest] = instance}, state ->
        if Dns.name_key(name) == state.service_key and Dns.name_key(rest) == state.service_key,
          do: touch_instance(state, instance, source),
          else: state

      _record, state ->
        state
    end)
  end

  defp touch_instance(state, [label | _] = instance, source) do
    key = {source, Dns.name_key(instance)}

    case state.instances do
      %{^key => entry} ->
        entry = %{entry | name: label, seq: state.seq}
        %{state | instances: Map.put(state.instances, key, entry)}

      instances when map_size(instances) < @max_instances ->
        entry = %{name: label, seq: state.seq, srv: nil, txt: nil}
        %{state | instances: Map.put(instances, key, entry)}

      _ ->
        state
    end
  end

  defp take_instance_records(state, records, source) do
    Enum.reduce(records, state, fn
      %{type: type, name: name, data: data}, state when type in [:srv, :txt] ->
        key = {source, Dns.name_key(name)}

        case state.instances do
          %{^key => entry} ->
            entry = Map.merge(entry, %{type => data, seq: state.seq})
            %{state | instances: Map.put(state.instances, key, entry)}

          _ ->
            state
        end

      _record, state ->
        state
    end)
  end

  defp take_addresses(state, records, source) do
    targets =
      for {{^source, _key}, %{srv: %{target: target}}} <- state.instances,
          into: MapSet.new(),
          do: Dns.name_key(target)

    Enum.reduce(records, state, fn
      %{type: :a, name: name, data: address}, state ->
        key = Dns.name_key(name)

        if MapSet.member?(targets, key),
          do: %{state | a: Map.put(state.a, {source, key}, address)},
          else: state

      _record, state ->
        state
    end)
  end

  defp follow_up(state, socket) do
    questions =
      state.instances
      |> Enum.flat_map(fn {{source, _key} = key, entry} ->
        instance_questions(key, entry, [entry.name | state.service]) ++
          address_question(state, source, entry)
      end)
      |> Enum.reject(fn {asked, _question} -> MapSet.member?(state.asked, asked) end)

    if questions == [] do
      state
    else
      id = query_id()

      packet =
        questions
        |> Enum.map(&elem(&1, 1))
        |> Enum.uniq_by(&{&1.type, Dns.name_key(&1.name)})
        |> Dns.encode_query(id)

      send_to(socket, Map.fetch!(state.sockets, socket), packet)
      asked = Enum.reduce(questions, state.asked, &MapSet.put(&2, elem(&1, 0)))
      %{state | asked: asked, ids: MapSet.put(state.ids, id)}
    end
  end

  defp instance_questions(key, entry, instance) do
    for type <- [:srv, :txt], Map.fetch!(entry, type) == nil do
      {{type, key}, %{name: instance, type: type}}
    end
  end

  defp address_question(state, source, entry) do
    case entry.srv do
      %{target: target} ->
        key = {source, Dns.name_key(target)}

        if is_map_key(state.a, key),
          do: [],
          else: [{{:a, key}, %{name: target, type: :a}}]

      _ ->
        []
    end
  end

  defp candidates(state) do
    state.instances
    |> Enum.flat_map(fn {{source, _key}, entry} ->
      case candidate(state, source, entry) do
        {:ok, candidate} -> [{entry.seq, candidate}]
        :error -> []
      end
    end)
    |> Enum.sort_by(fn {seq, _candidate} -> seq end)
    |> Map.new(fn {_seq, candidate} ->
      {{candidate.fp, candidate.inst, candidate.host, candidate.dist_port}, candidate}
    end)
    |> Map.values()
    |> Enum.sort_by(& &1.name)
  end

  defp candidate(state, source, entry) do
    txt = Dns.txt_map(entry.txt || [])

    with "1" <- Map.get(txt, "v", "1"),
         {:ok, inst} <- required(txt, "inst"),
         {:ok, node} <- required(txt, "node"),
         {:ok, fp_text} <- required(txt, "fp"),
         {:ok, <<_::256>> = fp} <- Base.url_decode64(fp_text, padding: false) do
      {:ok,
       %{
         name: entry.name,
         inst: inst,
         node: node,
         host: host(state, source, entry),
         port: port(txt["port"]),
         dist_port: port(txt["dport"]),
         fp: fp,
         firmware: txt["fw"],
         device: txt["dev"]
       }}
    else
      _ -> :error
    end
  end

  defp required(txt, key) do
    case txt do
      %{^key => value} when value != "" -> {:ok, value}
      _ -> :error
    end
  end

  defp host(state, {ip, _port} = source, entry) do
    address =
      case entry.srv do
        %{target: target} -> Map.get(state.a, {source, Dns.name_key(target)}, ip)
        _ -> ip
      end

    address |> :inet.ntoa() |> to_string()
  end

  defp port(nil), do: nil

  defp port(text) do
    case Integer.parse(text) do
      {port, ""} when port in 1..65_535 -> port
      _ -> nil
    end
  end

  defp query_id, do: :rand.uniform(0xFFFF)

  defp now, do: System.monotonic_time(:millisecond)
end
