defmodule MobPair.Pairings do
  @moduledoc """
  The host app's paired sibling apps (FMutate protocol §1.3–1.4): per-app
  cookies, pinned client certificates, revocation. One registry per node,
  registered as `MobPair.Pairings`.

  On Allow, `add/1` makes a cookie (32 random bytes, base64url), sets it for
  exactly the node name the sibling declared, and pins the sibling's
  certificate for TLS distribution. `revoke/1` (the host's Disconnect, or a
  sibling's unpair request) disconnects the node, replaces its cookie with a
  random one and unpins its certificate, so neither the old cookie nor the
  certificate opens a connection again.

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
  a process on every change.
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
  Writes `contents` to `path` readable by its owner only: created 0600
  before anything is written, then renamed into place. For files holding
  secrets (the host's private key, the pairings' cookies); keep them in
  app-private storage.
  """
  @spec write_private(Path.t(), iodata()) :: :ok | {:error, File.posix()}
  def write_private(path, contents) do
    tmp = "#{path}.tmp-#{System.unique_integer([:positive])}"

    with {:ok, io} <- File.open(tmp, [:write, :exclusive]),
         :ok <- File.chmod(tmp, 0o600),
         :ok <- IO.binwrite(io, contents),
         :ok <- File.close(io),
         :ok <- File.rename(tmp, path) do
      :ok
    else
      {:error, _} = error ->
        File.rm(tmp)
        error
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
      allow?: Keyword.get(opts, :allow_list, :auto) == :auto and plain_dist?(),
      subscribers: %{}
    }

    if Node.alive?() do
      if Keyword.get(opts, :default_cookie, :random) == :random,
        do: :erlang.set_cookie(random_cookie_atom())

      if state.allow?,
        do: :ok = :net_kernel.allow([@nobody | Keyword.get(opts, :also_allow, [])])
    end

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

    put(pairing, state)
    save(state)
    notify(state, :added, pairing)
    {:reply, {:ok, pairing}, state}
  end

  def handle_call({:revoke, node}, _from, state) do
    case :ets.take(@table, node) do
      [{^node, atom, pairing}] ->
        if Node.alive?() do
          :erlang.disconnect_node(atom)
          :erlang.set_cookie(atom, random_cookie_atom())
        end

        save(state)
        notify(state, :revoked, pairing)

      [] ->
        :ok
    end

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
