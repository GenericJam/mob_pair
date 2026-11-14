defmodule MobPair.Transport do
  @moduledoc """
  Erlang distribution from the joining app (Humdinger…) to a paired host app
  (FMutate, Magpie…): the joiner's node, the per-app cookie, the route to the
  host's port, and the connection.

  ## The joiner's node

  The joiner only ever connects out, so a node it starts itself
  (`start_node/1`) is hidden and has no listener (`dist_listen: false`):
  nothing on the phone or the Wi-Fi can connect in, and there is no epmd
  (`MobPair.Epmd` routes the host). Auto-connect is off
  (`dist_auto_connect: never`), so a message to a dropped host can't
  reconnect behind the app's back. Its default cookie is random; the host's
  node gets the pairing's cookie with `:erlang.set_cookie/2`.

  Which name to declare at pairing is the app's choice (the running node's,
  a development node's, or a fresh `random_node_name/1`); `connect/2` uses
  the running node when its name is the record's `self_node`, else starts
  one under that name.

  The connection to the host is hidden too (`:net_kernel.hidden_connect_node/1`):
  `global` doesn't mesh the joiner with the host's other peers. What to send
  over it (FMutate: casts to its `:fmutate_instance`) is the app's protocol.

  ## Carriers

  `dist_proto` from the pairing: `:inet_tcp` is plain distribution to the
  host's loopback port (same phone), refused to any other host
  (`{:error, :plain_distribution_off_loopback}`); `:inet_tls` goes through
  `MobPair.Tunnel` (mutual TLS, both certificates pinned).

  ## Atoms

  Node names and cookies are atoms. They are made only from the stored
  pairing (validated by `MobPair.Record`), and for TLS only after the
  tunnel has verified the host's certificate, so a peer on the network can't
  make the joiner create atoms.
  """

  alias MobPair.{Epmd, Record, Tunnel}

  require Logger

  @type conn :: %{node: node(), tunnel: pid() | nil}

  @callback connect(Record.t(), owner :: pid()) :: {:ok, conn()} | {:error, term()}
  @callback disconnect(conn()) :: :ok
  @callback revoke(node() | nil) :: :ok

  @behaviour __MODULE__

  @doc """
  Makes `MobPair.Epmd` the node's port mapper. Call before distribution
  starts (at app start, ahead of any development node); it also works later
  for outgoing connections, which look the module up each time.
  """
  @spec setup() :: :ok | {:error, term()}
  def setup do
    case {:init.get_argument(:epmd_module), :application.get_env(:kernel, :epmd_module)} do
      {:error, {:ok, Epmd}} -> :ok
      {:error, :undefined} -> :application.set_env(:kernel, :epmd_module, Epmd)
      configured -> unusable(configured)
    end
  end

  # Another port mapper is configured: the host can't be routed. The app runs
  # on; connecting will fail and say so.
  defp unusable(configured) do
    Logger.error(
      "MobPair: another epmd module is configured (#{inspect(configured)}); the host can't be routed"
    )

    {:error, {:epmd_module, configured}}
  end

  @doc """
  A fresh node name `"<prefix>_<8 base32>@127.0.0.1"`, unique per pairing so
  two phones paired with one host don't collide (the host part is only a
  label: nothing ever resolves it).
  """
  @spec random_node_name(String.t()) :: String.t()
  def random_node_name(prefix), do: "#{prefix}_#{random_id()}@127.0.0.1"

  @doc """
  Connects to the paired host. `owner` owns the TLS tunnel (it closes
  when `owner` exits). The record is validated first (`Record.validate/1`):
  its names and cookie become atoms.
  """
  @impl true
  def connect(%Record{} = record, owner) do
    with :ok <- safe_carrier(record),
         {:ok, record} <- Record.validate(record),
         :ok <- ensure_node(record.self_node),
         {:ok, route, tunnel} <- open_route(record, owner) do
      node = String.to_atom(record.node)
      true = :erlang.set_cookie(node, String.to_atom(record.cookie))
      :ok = Epmd.put_route(node, route)

      if :net_kernel.hidden_connect_node(node) == true do
        {:ok, %{node: node, tunnel: tunnel}}
      else
        disconnect(%{node: node, tunnel: tunnel})
        {:error, if(tunnel, do: :rejected, else: :unreachable)}
      end
    end
  end

  @doc "Drops the connection (the pairing stays)."
  @impl true
  def disconnect(%{node: node, tunnel: tunnel}) do
    :erlang.disconnect_node(node)
    if tunnel, do: Tunnel.close(tunnel)
    Epmd.delete_route(node)
  end

  @doc "Disconnects `node` and replaces its cookie with a random one."
  @impl true
  def revoke(nil), do: :ok

  def revoke(node) when is_atom(node) do
    :erlang.disconnect_node(node)
    if Node.alive?(), do: :erlang.set_cookie(node, random_cookie())
    Epmd.delete_route(node)
  end

  defp ensure_node(name) do
    cond do
      Node.alive?() and Atom.to_string(node()) == name -> :ok
      Node.alive?() -> {:error, {:node_name, node()}}
      true -> start_node(name)
    end
  end

  @doc """
  Starts this VM's distribution as `name` (`"short@host"`): hidden, no
  listener, no auto-connect, a random default cookie, `MobPair.Epmd` as port
  mapper. `{:error, {:node_name, node}}` if it already runs as another node,
  `{:error, {:invalid, :self_node}}` for a name `Record.self_node?/1` refuses.
  """
  @spec start_node(String.t()) :: :ok | {:error, term()}
  def start_node(name) do
    with :ok <- valid_name(name),
         :ok <- setup() do
      # auth reads or creates $HOME/.config/erlang/.erlang.cookie when the
      # node starts (Android has no such directory until made).
      if System.get_env("MOB_BEAMS_DIR") && System.get_env("HOME"),
        do: File.mkdir_p(Path.join([System.get_env("HOME"), ".config", "erlang"]))

      :application.set_env(:kernel, :dist_auto_connect, :never)
      options = %{name_domain: :longnames, dist_listen: false, hidden: true}

      case :net_kernel.start(String.to_atom(name), options) do
        {:ok, _} ->
          :erlang.set_cookie(random_cookie())
          :ok

        {:error, {:already_started, _}} ->
          ensure_node(name)

        {:error, reason} ->
          {:error, {:distribution, reason}}
      end
    end
  end

  defp valid_name(name),
    do: if(Record.self_node?(name), do: :ok, else: {:error, {:invalid, :self_node}})

  # Plain distribution checks the cookie in the handshake and nothing after
  # it: anyone on the path could inject messages (code) into both nodes. Only
  # over loopback, whatever the record says (Record.validate/1 refuses it too).
  defp safe_carrier(%Record{dist_proto: :inet_tls}), do: :ok

  defp safe_carrier(%Record{dist_proto: :inet_tcp} = record) do
    if Record.loopback?(record), do: :ok, else: {:error, :plain_distribution_off_loopback}
  end

  defp open_route(%Record{dist_proto: :inet_tcp} = record, _owner) do
    {:ok, ip} = :inet.parse_strict_address(String.to_charlist(record.host))
    {:ok, {ip, record.dist_port}, nil}
  end

  defp open_route(%Record{dist_proto: :inet_tls} = record, owner) do
    with {:ok, tunnel, port} <- Tunnel.open(record, owner) do
      {:ok, {{127, 0, 0, 1}, port}, tunnel}
    end
  end

  defp random_id,
    do: 5 |> :crypto.strong_rand_bytes() |> Base.encode32(case: :lower, padding: false)

  # One fresh atom per call; called once per node start and once per revoke.
  defp random_cookie,
    do: 32 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false) |> String.to_atom()
end
