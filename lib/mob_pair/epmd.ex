defmodule MobPair.Epmd do
  @moduledoc """
  The distribution port mapper Humdinger's node uses (kernel `epmd_module`):
  FMutate is found without any epmd.

  Each app on a phone runs its own BEAM, so a shared epmd would die with
  whichever app started it (protocol §2). FMutate listens on a fixed port per
  instance instead, and the pairing record says which. `MobPair.Transport`
  puts a route for FMutate's node here before connecting (the loopback
  tunnel's port for TLS distribution), and `address_please/3` answers with it
  directly, so no lookup ever leaves the phone.

  Every other node goes to OTP's `erl_epmd`, so development tooling keeps
  working: `Mob.Dist` registers the dev node with the Mac's epmd through
  `adb reverse`, and that registration still goes through here.

  The module must be set before distribution starts (`Transport.setup/0`,
  called from `App.on_start` ahead of `Mob.Dist`): net_kernel starts its port
  mapper once.
  """

  @routes {__MODULE__, :routes}
  # Distribution protocol version 6 (OTP 23+), what FMutate's node speaks.
  @version 6

  @doc "Routes `node` (an atom or `\"name@host\"`) to `{ip, port}`."
  @spec put_route(node() | String.t(), {:inet.ip_address(), :inet.port_number()}) :: :ok
  def put_route(node, {ip, port}) when is_tuple(ip) and port in 1..65_535 do
    :persistent_term.put(@routes, Map.put(routes(), to_string(node), {ip, port}))
  end

  @doc "Removes `node`'s route."
  @spec delete_route(node() | String.t()) :: :ok
  def delete_route(node) do
    routes = routes()
    key = to_string(node)
    if Map.has_key?(routes, key), do: :persistent_term.put(@routes, Map.delete(routes, key))
    :ok
  end

  @doc "The route for `node`, if any."
  @spec route(node() | String.t()) :: {:inet.ip_address(), :inet.port_number()} | nil
  def route(node), do: Map.get(routes(), to_string(node))

  # The epmd_module callbacks (see erl_epmd).

  @doc false
  @spec start_link() :: :ignore | {:ok, pid()} | {:error, term()}
  def start_link, do: :erl_epmd.start_link()

  @doc false
  @spec register_node(atom(), :inet.port_number()) :: {:ok, integer()} | {:error, term()}
  def register_node(name, port), do: :erl_epmd.register_node(name, port)

  @doc false
  @spec register_node(atom(), :inet.port_number(), atom()) :: {:ok, integer()} | {:error, term()}
  def register_node(name, port, family), do: :erl_epmd.register_node(name, port, family)

  @doc false
  @spec listen_port_please(atom(), term()) :: {:ok, :inet.port_number()}
  def listen_port_please(name, host), do: :erl_epmd.listen_port_please(name, host)

  @doc false
  @spec port_please(atom(), term()) :: term()
  def port_please(name, host), do: port_please(name, host, :infinity)

  @doc false
  @spec port_please(atom(), term(), timeout()) :: term()
  def port_please(name, host, timeout) do
    case lookup(name, host) do
      {_ip, port} -> {:port, port, @version}
      nil -> :erl_epmd.port_please(name, host, timeout)
    end
  end

  @doc false
  @spec address_please(atom(), term(), atom()) :: term()
  def address_please(name, host, family) do
    case lookup(name, host) do
      {ip, port} -> {:ok, ip, port, @version}
      nil -> :erl_epmd.address_please(name, host, family)
    end
  end

  @doc false
  @spec names(term()) :: {:ok, list()} | {:error, term()}
  def names(host), do: :erl_epmd.names(host)

  defp lookup(name, host) when is_list(host) or is_atom(host),
    do: route("#{name}@#{host}")

  defp lookup(name, host) when is_tuple(host),
    do: route("#{name}@#{:inet.ntoa(host)}")

  defp routes, do: :persistent_term.get(@routes, %{})
end
