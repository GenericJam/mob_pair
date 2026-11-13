defmodule MobPair.Pairings do
  @moduledoc """
  The host app's paired sibling apps (FMutate protocol §1.3–1.4): per-app
  cookies, pinned client certificates, revocation. One registry per node,
  registered as `MobPair.Pairings`.

  On Allow, `add/1` makes a cookie (32 random bytes, base64url), sets it for
  exactly the node name the sibling declared, and pins the sibling's
  certificate for TLS distribution; a pairing it replaces (same node name)
  is revoked first. `revoke/1` (the host's Disconnect, or a sibling's unpair
  request) replaces the node's cookie with a random one, aborts a
  distribution handshake of that node already under way, disconnects it and
  unpins its certificate, so neither the old cookie nor the certificate
  opens a connection again; a connection of a revoked name that still comes
  up is dropped at `nodeup`. Revoking can't undo what a connected node
  already did: distribution is full trust.

  ## Distribution started after the registry

  Cookies, the default cookie and the allow list belong to the running
  node. A host whose distribution starts at runtime (a Mob app) starts the
  registry with its other processes and calls `distribution_started/0`
  once `Node.start/2` returned; until then paired siblings can't connect.

  TLS distribution checks client certificates with `verify_client/4`; write
  the `-ssl_dist_optfile` with `write_ssl_dist_optfile/2`. A TLS front that
  terminates TLS itself finds the node pinned to a client certificate with
  `node_for_fp/1`.

  ## Options

    * `:store` – `{module, opts}` implementing `MobPair.Pairings.Store`
      (e.g. `MobPair.Pairings.FileStore`), default nil (memory only). At
      start the stored pairings are restored (cookies set per node); every
      `add/1` and `revoke/1` saves the full list.
    * `:default_cookie` – `:random` (default) replaces the node's default
      cookie with 32 random bytes, so a connection under any unpaired name
      can't pass the challenge; `:keep` leaves it (e.g. a development
      tool's cookie).
    * `:allow_list` – `:auto` (default): with plain (loopback) distribution,
      restrict it to the paired node names with `:net_kernel.allow/1` (plus
      `:also_allow`, e.g. a development host), so a connection under any
      other name is refused before the cookie check. `allow/1` only ever adds
      names; a revoked name stays allowed but its cookie is random, so it
      can't get in. `false` never touches the allow list.
    * `:also_allow` – extra node names (atoms) for the allow list.

  With TLS distribution the allow list isn't used: `inet_tls_dist` turns it
  into a check that the client certificate names the node's host, which the
  pinned self-signed certificates don't. There a connection needs a pinned
  certificate (`verify_client/4`) and the per-node cookie of the name it
  declares; any unpaired name meets the random default cookie.

  `subscribe/1` sends `{:mob_pair_pairings, :added | :revoked, pairing}` to
  a process on every change (a replaced pairing: `:revoked` for the old one,
  then `:added`).
  """

  use GenServer

  alias MobPair.Cert

  require Logger

  @table __MODULE__

  @type pairing :: %{
          node: String.t(),
          app_id: String.t(),
          app_name: String.t(),
          device_name: String.t(),
          client_fp: <<_::256>>,
          dist_proto: :inet_tcp | :inet_tls | nil,
          cookie: String.t(),
          paired_at: integer()
        }

  @fields [:node, :app_id, :app_name, :device_name, :client_fp, :dist_proto]

  @doc false
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}

  @doc "Starts the registry (one per node); see the moduledoc for options."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc """
  Adds (or replaces) the pairing for `request.node` and returns it with its
  new cookie. `request`: `%{node, app_id, app_name, device_name, client_fp,
  dist_proto}` (`dist_proto`: the carrier granted); a `cookie` and
  `paired_at` in it are reused (restoring stored pairings).
  """
  @spec add(map()) :: {:ok, pairing()}
  def add(request), do: GenServer.call(__MODULE__, {:add, request})

  @doc """
  Applies the pairings to the node once its distribution runs (see the
  moduledoc): the per-node cookies, the `:default_cookie` and `:allow_list`
  options, and the `nodeup` watch for revoked names. Called by `start_link/1`
  when the node is already alive; call it again after starting distribution
  later (or restarting it). Idempotent.
  """
  @spec distribution_started() :: :ok
  def distribution_started, do: GenServer.call(__MODULE__, :distribution_started)

  @doc "Revokes the pairing of `node` (a string or atom)."
  @spec revoke(node() | String.t()) :: :ok
  def revoke(node), do: GenServer.call(__MODULE__, {:revoke, to_string(node)})

  @doc "The pairing of `node` (a string), or nil."
  @spec get(String.t()) :: pairing() | nil
  def get(node) do
    case :ets.lookup(@table, node) do
      [{^node, _atom, pairing}] -> pairing
      [] -> nil
    end
  end

  @doc "All pairings."
  @spec list() :: [pairing()]
  def list, do: for({_node, _atom, pairing} <- :ets.tab2list(@table), do: pairing)

  @doc "Whether a client certificate fingerprint belongs to a paired sibling."
  @spec pinned?(binary()) :: boolean()
  def pinned?(fp), do: node_for_fp(fp) != nil

  @doc "The node name of the pairing that pinned the client certificate `fp`, or nil."
  @spec node_for_fp(binary()) :: String.t() | nil
  def node_for_fp(fp) do
    case :ets.match_object(@table, {:_, :_, %{client_fp: fp}}) do
      [{node, _atom, _pairing} | _] -> node
      [] -> nil
    end
  end

  @doc "Sends `pid` `{:mob_pair_pairings, :added | :revoked, pairing}` on every change."
  @spec subscribe(pid()) :: :ok
  def subscribe(pid), do: GenServer.call(__MODULE__, {:subscribe, pid})

  @doc """
  `ssl` verify fun for the host's TLS distribution listener: accepts a client
  certificate only if a pairing pinned it.
  """
  @spec verify_client(term(), binary(), term(), term()) ::
          {:valid, term()} | {:fail, term()} | {:unknown, term()}
  def verify_client(otp_cert, der, event, state) do
    {fun, _} = Cert.verify_fun(&pinned?/1)
    fun.(otp_cert, der, event, state)
  end

  @doc """
  Writes the `-ssl_dist_optfile` for the host's TLS distribution: its
  certificate and key, mutual TLS 1.3, clients checked by `verify_client/4`.
  """
  @spec write_ssl_dist_optfile(Path.t(), Cert.t()) :: :ok | {:error, File.posix()}
  def write_ssl_dist_optfile(path, %{cert: cert, key: key}) do
    write_private(path, """
    [{server,
      [{certs_keys, [\#{cert => #{erlang_binary(cert)}, key => {'ECPrivateKey', #{erlang_binary(key)}}}]},
       {verify, verify_peer},
       {cacerts, []},
       {fail_if_no_peer_cert, true},
       {verify_fun, {fun '#{__MODULE__}':verify_client/4, []}},
       {versions, ['tlsv1.3']}]},
     {client,
      [{verify, verify_peer},
       {cacerts, []},
       {verify_fun, {fun '#{__MODULE__}':verify_client/4, []}},
       {versions, ['tlsv1.3']}]}].
    """)
  end

  @doc """
  Writes `contents` to `path` readable by its owner only: written in a new
  0700 directory next to `path` (so no other user can open the file before
  it is 0600), synced to disk, then renamed into place. For files holding
  secrets (the host's private key, the pairings' cookies); keep them in
  app-private storage.
  """
  @spec write_private(Path.t(), iodata()) :: :ok | {:error, File.posix()}
  def write_private(path, contents) do
    dir = "#{path}.tmp-#{System.unique_integer([:positive])}"
    tmp = Path.join(dir, "contents")

    with :ok <- File.mkdir(dir),
         :ok <- File.chmod(dir, 0o700),
         :ok <- write_synced(tmp, contents),
         :ok <- File.rename(tmp, path) do
      File.rmdir(dir)
      :ok
    else
      {:error, _} = error ->
        File.rm_rf(dir)
        error
    end
  end

  defp write_synced(path, contents) do
    with {:ok, io} <- File.open(path, [:write, :exclusive, :raw, :binary]) do
      try do
        with :ok <- File.chmod(path, 0o600),
             :ok <- :file.write(io, contents),
             do: :file.sync(io)
      after
        :file.close(io)
      end
    end
  end

  defp erlang_binary(bytes), do: "<<" <> Enum.join(:binary.bin_to_list(bytes), ",") <> ">>"

  # net_kernel enforces the allow list only once it is non-empty; this name
  # never connects.
  @nobody :nobody@invalid

  @impl true
  def init(opts) do
    :ets.new(@table, [:named_table, :protected, read_concurrency: true])

    state = %{
      store: Keyword.get(opts, :store),
      default_cookie: Keyword.get(opts, :default_cookie, :random),
      allow_list: Keyword.get(opts, :allow_list, :auto),
      also_allow: Keyword.get(opts, :also_allow, []),
      allow?: false,
      monitoring: nil,
      revoked: MapSet.new(),
      subscribers: %{}
    }

    state = apply_distribution(state)
    Enum.each(load(state.store), &put(&1, state))
    {:ok, state}
  end

  @impl true
  def handle_call({:add, request}, _from, state) do
    pairing =
      request
      |> Map.take(@fields)
      |> Map.put_new(:dist_proto, nil)
      |> Map.merge(%{
        cookie:
          request[:cookie] ||
            32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false),
        paired_at: request[:paired_at] || System.os_time(:second)
      })

    # The pairing this one replaces loses its cookie and its connection first.
    state = cut(state, pairing.node)
    put(pairing, state)

    state = %{
      state
      | revoked: MapSet.delete(state.revoked, String.to_existing_atom(pairing.node))
    }

    save(state)
    notify(state, :added, pairing)
    {:reply, {:ok, pairing}, state}
  end

  def handle_call({:revoke, node}, _from, state) do
    state = cut(state, node)
    save(state)
    {:reply, :ok, state}
  end

  def handle_call(:distribution_started, _from, state) do
    state = apply_distribution(state)
    for {_node, _atom, pairing} <- :ets.tab2list(@table), do: put(pairing, state)
    {:reply, :ok, state}
  end

  def handle_call({:subscribe, pid}, _from, state) do
    subscribers =
      if pid in Map.values(state.subscribers),
        do: state.subscribers,
        else: Map.put(state.subscribers, Process.monitor(pid), pid)

    {:reply, :ok, %{state | subscribers: subscribers}}
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state),
    do: {:noreply, %{state | subscribers: Map.delete(state.subscribers, ref)}}

  # A handshake of a revoked name that got past cut/2 (it had read the old
  # cookie while another connection of that name was up): dropped at once.
  def handle_info({:nodeup, node, _info}, state) do
    if MapSet.member?(state.revoked, node), do: :erlang.disconnect_node(node)
    {:noreply, state}
  end

  def handle_info({:nodedown, _node, _info}, state), do: {:noreply, state}

  # Revokes the pairing of `node` (if any): unpinned, a random cookie (first,
  # so a handshake starting now fails), the handshake already under way
  # aborted (net_kernel's disconnect leaves pending connections alone, and
  # dist_util read the cookie when it marked the connection pending), the
  # connection cut, subscribers told.
  defp cut(state, node) do
    case :ets.take(@table, node) do
      [{^node, atom, pairing}] ->
        if Node.alive?() do
          :erlang.set_cookie(atom, random_cookie_atom())
          abort_handshake(atom)
          :erlang.disconnect_node(atom)
        end

        notify(state, :revoked, pairing)
        %{state | revoked: MapSet.put(state.revoked, atom)}

      [] ->
        state
    end
  end

  defp abort_handshake(atom) do
    case :net_kernel.node_info(atom) do
      {:ok, info} ->
        if info[:state] == :pending, do: Process.exit(info[:owner], :kill)

      {:error, _} ->
        :ok
    end
  end

  # The node-wide settings, once distribution runs (else at the next
  # distribution_started/0).
  defp apply_distribution(state) do
    if Node.alive?() do
      if state.default_cookie == :random, do: :erlang.set_cookie(random_cookie_atom())
      allow? = state.allow_list == :auto and plain_dist?()
      if allow?, do: :ok = :net_kernel.allow([@nobody | state.also_allow])
      %{watch_nodes(state) | allow?: allow?}
    else
      state
    end
  end

  # One nodeup subscription per net_kernel (a restarted distribution needs a new one).
  defp watch_nodes(state) do
    case Process.whereis(:net_kernel) do
      kernel when kernel == state.monitoring ->
        state

      kernel ->
        :ok = :net_kernel.monitor_nodes(true, node_type: :all)
        %{state | monitoring: kernel}
    end
  end

  # The atoms are the node the user allowed and its cookie: one pair per
  # pairing, never made from an unapproved request.
  defp put(pairing, state) do
    atom = String.to_atom(pairing.node)

    if Node.alive?() do
      :erlang.set_cookie(atom, String.to_atom(pairing.cookie))
      if state.allow?, do: :ok = :net_kernel.allow([atom])
    end

    :ets.insert(@table, {pairing.node, atom, pairing})
  end

  defp load(nil), do: []

  defp load({module, opts}) do
    case module.load(opts) do
      {:ok, pairings} ->
        pairings

      {:error, reason} ->
        Logger.warning("MobPair.Pairings: stored pairings unreadable: #{inspect(reason)}")
        []
    end
  end

  defp save(%{store: nil}), do: :ok

  defp save(%{store: {module, opts}}) do
    case module.save(list(), opts) do
      :ok -> :ok
      {:error, reason} -> Logger.warning("MobPair.Pairings: saving failed: #{inspect(reason)}")
    end
  end

  defp notify(state, event, pairing) do
    for {_ref, pid} <- state.subscribers, do: send(pid, {:mob_pair_pairings, event, pairing})
  end

  defp plain_dist? do
    case :init.get_argument(:proto_dist) do
      {:ok, [[proto | _] | _]} -> proto != ~c"inet_tls"
      _ -> true
    end
  end

  defp random_cookie_atom,
    do: 32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false) |> String.to_atom()
end
