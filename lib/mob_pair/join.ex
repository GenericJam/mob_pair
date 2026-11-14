defmodule MobPair.Join do
  @moduledoc """
  Joining a host app (FMutate, Magpie…), for the joining app's Pair screen.

  Three ways in, all ending in the same exchange (`MobPair.Client`, FMutate
  protocol §1.5): a scanned QR code or a pasted link (`parse_link/2`, then
  `pair/3` with the parsed link), or the 8-character code typed in (`pair/3`
  with `%{code: code}`), which finds hosts of the service over mDNS and tries
  each one that is pairing.

  One owner (the screen) at a time. Messages to the owner:

    * `{:mob_pair, :found, [candidate]}` while `discover/2` runs: each time
      the list of hosts nearby changes (`MobPair.Discovery` candidates:
      `%{name, inst, node, host, source, port, dist_port, fp, firmware,
      device}`; `port` is nil when that host isn't showing its Pair screen).
    * `{:mob_pair, :matched, candidate}`: the host proved itself and took
      the token or code ("code matches" on its screen).
    * `{:mob_pair, :waiting}`: the host is asking its user (Allow).
    * `{:mob_pair, :paired, info}`: `:install` accepted the record; `info` is
      `%{name, device, firmware, inst, same_phone}`.
    * `{:mob_pair, :failed, reason}`: see `MobPair.Client.pair/4`, plus
      `:not_found` (no host showing its code nearby) and `{:store, reason}`
      (`:install` refused the record).

  `cancel/1` stops discovery and any pairing in progress (closing the
  connection withdraws the request on the host).

  The device name shown on the host's Allow sheet is `:device_name`. On
  Android `:inet.gethostname/0` says "localhost"; Humdinger reads the model
  with `/system/bin/getprop ro.product.model` (readable by any app) and
  passes it.
  """

  use GenServer

  alias MobPair.{Cert, Client, Code, Discovery, Link, Record}

  require Logger

  @discovery_interval 2_000
  @fresh_candidates_ms 5_000
  @max_tries 8

  @typedoc "What `pair/2` takes: a parsed link, or a typed code (optionally for one candidate)."
  @type offer :: Link.t() | %{required(:code) => String.t(), optional(:candidate) => map()}

  @doc false
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}

  @doc """
  Starts the joining service. Options:

    * `:service` (required): the host app's service name (`"fmutate"`);
    * `:app_name` (required) and `:app_id` (default `:app_name`): what the
      host's Allow sheet shows;
    * `:self_node` (required): a 0-arity function returning the node name to
      declare (see `MobPair.Transport`);
    * `:install` (required): a 1-arity function receiving the
      `MobPair.Record`, returning `:ok` or `{:error, reason}` (the app stores
      it and starts its link);
    * `:device_name`: a string or a 0-arity function (default the host name);
    * `:discovery`: a function of browse options returning
      `{:ok, candidates}` (default `MobPair.Discovery.browse/1`) and
      `:discovery_opts` (`service:` is added);
    * `:link_services`: the services whose links `parse_link/2` accepts
      (default `[service]`);
    * `:name` (default `MobPair.Join`; nil for none).
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    case Keyword.get(opts, :name, __MODULE__) do
      nil -> GenServer.start_link(__MODULE__, opts)
      name -> GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  @doc """
  Parses a scanned or pasted pairing link (see `MobPair.Link`) for one of
  the service's `:link_services`.
  """
  @spec parse_link(String.t(), GenServer.server()) :: {:ok, Link.t()} | {:error, term()}
  def parse_link(link, server \\ __MODULE__),
    do: Link.parse(link, services: GenServer.call(server, :link_services))

  @doc """
  The display form of a typed code (`{:ok, "KQ7M-X2PD"}`) or
  `{:error, :invalid_code}`. Case, spaces and dashes don't matter; `I`/`L`
  read as `1` and `O` as `0` (see `MobPair.Code`).
  """
  @spec normalize_code(String.t()) :: {:ok, String.t()} | {:error, :invalid_code}
  def normalize_code(input) do
    case Code.normalize(input) do
      {:ok, code} -> {:ok, Code.format(code)}
      :error -> {:error, :invalid_code}
    end
  end

  @doc "Looks for hosts of the service nearby until `cancel/1` (or the owner exits)."
  @spec discover(pid(), GenServer.server()) :: :ok
  def discover(owner \\ self(), server \\ __MODULE__),
    do: GenServer.call(server, {:discover, owner})

  @doc "Pairs using `offer`, replacing any pairing in progress."
  @spec pair(pid(), offer(), GenServer.server()) :: :ok | {:error, :invalid_code}
  def pair(owner \\ self(), offer, server \\ __MODULE__),
    do: GenServer.call(server, {:pair, owner, offer})

  @doc "Stops discovery and the pairing in progress."
  @spec cancel(GenServer.server()) :: :ok
  def cancel(server \\ __MODULE__), do: GenServer.call(server, :cancel)

  @impl true
  def init(opts) do
    service = Keyword.fetch!(opts, :service)
    app_name = Keyword.fetch!(opts, :app_name)

    state = %{
      service: service,
      app_id: Keyword.get(opts, :app_id, app_name),
      app_name: app_name,
      install: Keyword.fetch!(opts, :install),
      self_node: Keyword.fetch!(opts, :self_node),
      device_name: Keyword.get(opts, :device_name, &hostname/0),
      link_services: Keyword.get(opts, :link_services, [service]),
      discovery: Keyword.get(opts, :discovery, &Discovery.browse/1),
      discovery_opts: Keyword.put(Keyword.get(opts, :discovery_opts, []), :service, service),
      owner: nil,
      owner_ref: nil,
      discoverer: nil,
      pairer: nil,
      candidates: [],
      found_at: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:discover, owner}, _from, state) do
    state = state |> own(owner) |> stop_discovery()
    {:reply, :ok, start_discovery(state)}
  end

  def handle_call({:pair, owner, offer}, _from, state) do
    case target(offer, state) do
      {:ok, candidates_and_auth} ->
        state = state |> own(owner) |> stop_pairing()
        {:reply, :ok, start_pairing(state, candidates_and_auth)}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  def handle_call(:link_services, _from, state), do: {:reply, state.link_services, state}

  def handle_call(:cancel, _from, state) do
    {:reply, :ok, state |> stop_discovery() |> stop_pairing() |> disown()}
  end

  @impl true
  def handle_info({:found, pid, candidates}, %{discoverer: pid} = state) do
    if candidates != state.candidates, do: send(state.owner, {:mob_pair, :found, candidates})
    {:noreply, %{state | candidates: candidates, found_at: now()}}
  end

  def handle_info({:paired, pid, record, candidate}, %{pairer: pid} = state) do
    message =
      case state.install.(record) do
        :ok -> {:mob_pair, :paired, info(record, candidate)}
        {:error, reason} -> {:mob_pair, :failed, {:store, reason}}
      end

    send(state.owner, message)
    {:noreply, stop_discovery(%{state | pairer: nil})}
  end

  def handle_info({:pair_failed, pid, reason}, %{pairer: pid} = state) do
    send(state.owner, {:mob_pair, :failed, reason})
    {:noreply, %{state | pairer: nil}}
  end

  def handle_info({:DOWN, ref, :process, _, _}, %{owner_ref: ref} = state) do
    {:noreply, state |> stop_discovery() |> stop_pairing() |> disown()}
  end

  def handle_info({:DOWN, _ref, :process, pid, reason}, %{pairer: pid} = state) do
    send(state.owner, {:mob_pair, :failed, {:crashed, reason}})
    {:noreply, %{state | pairer: nil}}
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, %{discoverer: pid} = state) do
    {:noreply, %{state | discoverer: nil}}
  end

  # Results and exits of discoverers and pairers that were replaced or cancelled.
  def handle_info(_stale, state), do: {:noreply, state}

  defp target(%{via: :link} = link, state) do
    {:ok, {[candidate_from_link(state.service, link)], {:token, link.token}}}
  end

  defp target(%{code: code} = offer, _state) do
    case Code.normalize(code) do
      {:ok, code} -> {:ok, {chosen(offer), {:code, code}}}
      :error -> {:error, :invalid_code}
    end
  end

  defp target(_offer, _state), do: {:error, :invalid_offer}

  # nil: look the candidates up when pairing starts.
  defp chosen(%{candidate: candidate}) when is_map(candidate), do: [candidate]
  defp chosen(_offer), do: nil

  defp candidate_from_link(service, link) do
    %{
      name: String.capitalize(service) <> " " <> String.upcase(link.inst),
      inst: link.inst,
      node: link.node,
      host: link.host,
      port: link.port,
      dist_port: nil,
      fp: link.fp,
      firmware: nil,
      device: nil
    }
  end

  defp own(%{owner: owner} = state, owner), do: state

  defp own(state, owner) do
    state = state |> stop_discovery() |> stop_pairing() |> disown()
    %{state | owner: owner, owner_ref: Process.monitor(owner)}
  end

  defp disown(%{owner_ref: nil} = state), do: state

  defp disown(state) do
    Process.demonitor(state.owner_ref, [:flush])
    %{state | owner: nil, owner_ref: nil}
  end

  defp start_discovery(state) do
    server = self()
    browse = state.discovery
    opts = state.discovery_opts

    {pid, _ref} =
      spawn_monitor(fn -> discovery_loop(server, browse, opts) end)

    %{state | discoverer: pid}
  end

  defp discovery_loop(server, browse, opts) do
    case browse.(opts) do
      {:ok, candidates} -> send(server, {:found, self(), candidates})
      {:error, reason} -> Logger.debug("MobPair discovery: #{inspect(reason)}")
    end

    Process.sleep(@discovery_interval)
    discovery_loop(server, browse, opts)
  end

  defp stop_discovery(%{discoverer: nil} = state), do: state

  defp stop_discovery(state) do
    Process.exit(state.discoverer, :kill)
    %{state | discoverer: nil}
  end

  defp start_pairing(state, {candidates, auth}) do
    server = self()

    context = %{
      owner: state.owner,
      identity: %{
        app_id: state.app_id,
        app_name: state.app_name,
        device_name: device_name(state.device_name),
        node: state.self_node.(),
        cert: Cert.self_signed(state.app_name)
      },
      service: state.service,
      candidates: candidates || fresh_candidates(state),
      browse: fn -> browse(state) end
    }

    {pid, _ref} = spawn_monitor(fn -> run_pairing(server, context, auth) end)
    %{state | pairer: pid}
  end

  defp stop_pairing(%{pairer: nil} = state), do: state

  defp stop_pairing(state) do
    Process.exit(state.pairer, :kill)
    %{state | pairer: nil}
  end

  defp fresh_candidates(%{found_at: nil}), do: nil
  defp fresh_candidates(%{candidates: []}), do: nil

  defp fresh_candidates(%{found_at: found_at, candidates: candidates}) do
    if now() - found_at < @fresh_candidates_ms, do: candidates
  end

  defp browse(state) do
    case state.discovery.(state.discovery_opts) do
      {:ok, candidates} -> candidates
      {:error, _} -> []
    end
  end

  # Runs in its own process: tries each candidate in turn until one pairs.
  # mDNS is unauthenticated: only unicast IPv4 (or this phone) is tried, at
  # most @max_tries hosts per code, and taken in turns from each source
  # address (in random order), so forged answers can't stall the pairing for
  # long, crowd the genuine host out of the tries, or send it to multicast
  # or unspecified addresses.
  defp run_pairing(server, context, auth) do
    candidates =
      (context.candidates || context.browse.())
      |> Enum.filter(&(&1.port && (Record.remote_unicast?(&1.host) or loopback?(&1.host))))
      |> interleave()
      |> Enum.take(@max_tries)

    case try_candidates(candidates, context, auth, :not_found) do
      {:ok, record, candidate} -> send(server, {:paired, self(), record, candidate})
      {:error, reason} -> send(server, {:pair_failed, self(), reason})
    end
  end

  # One candidate from each source address in turn, the sources shuffled.
  defp interleave(candidates) do
    candidates
    |> Enum.group_by(&Map.get(&1, :source, &1.host))
    |> Map.values()
    |> Enum.shuffle()
    |> round_robin([])
  end

  defp round_robin([], taken), do: Enum.reverse(taken)

  defp round_robin(groups, taken) do
    firsts = Enum.map(groups, &hd/1)
    rests = for [_ | rest] <- groups, rest != [], do: rest
    round_robin(rests, Enum.reverse(firsts, taken))
  end

  defp loopback?(host), do: is_binary(host) and Record.loopback?(host)

  defp try_candidates([], _context, _auth, reason), do: {:error, reason}

  defp try_candidates([candidate | rest], context, auth, best) do
    target = %{
      service: context.service,
      host: candidate.host,
      port: candidate.port,
      inst: candidate.inst,
      fp: link_fp(auth, candidate)
    }

    proven = make_ref()

    notify = fn
      :authenticated ->
        send(self(), proven)
        send(context.owner, {:mob_pair, :matched, candidate})

      :pending ->
        send(context.owner, {:mob_pair, :waiting})
    end

    case Client.pair(target, auth, context.identity, notify) do
      {:ok, record} ->
        {:ok, record, candidate}

      {:error, reason} = error ->
        # A typed code may belong to another host nearby, and anyone can
        # answer mDNS: whatever went wrong before this host proved it knows
        # the code (unreachable, busy, a wrong code, a bad or missing SRP
        # proof, a protocol error) is this candidate's, so keep looking.
        if match?({:code, _}, auth) and not proven?(proven),
          do: try_candidates(rest, context, auth, better(best, reason)),
          else: error
    end
  end

  defp proven?(proven) do
    receive do
      ^proven -> true
    after
      0 -> false
    end
  end

  # Only a link carries the fingerprint to pin; a code proves it via SRP.
  defp link_fp({:token, _}, candidate), do: candidate.fp
  defp link_fp({:code, _}, _candidate), do: nil

  # The error to report when no candidate pairs: a wrong code says the most.
  defp better({:wrong_code, _} = best, _reason), do: best
  defp better(_best, reason), do: reason

  defp info(record, candidate) do
    %{
      name: record.name || candidate.name,
      device: record.device || candidate.device,
      firmware: record.firmware || candidate.firmware,
      inst: record.inst,
      same_phone: Record.loopback?(record)
    }
  end

  defp device_name(name) when is_function(name, 0), do: name.()
  defp device_name(name) when is_binary(name), do: name

  defp hostname do
    {:ok, host} = :inet.gethostname()
    List.to_string(host)
  end

  defp now, do: System.monotonic_time(:millisecond)
end
