defmodule MobPair.FixedEpmd do
  @moduledoc """
  FMutate's port mapper (reference): no epmd, one fixed distribution port.

  FMutate runs its own BEAM and must not depend on an epmd another app
  started (protocol §2). Start its node with `MobPair.boot_args/1`:

      -start_epmd false -epmd_module Elixir.MobPair.FixedEpmd
      -kernel erl_epmd_node_listen_port <dist_port>
      -proto_dist inet_tls -ssl_dist_optfile <file>          (siblings on other phones)
      -kernel inet_dist_use_interface {127,0,0,1}            (plain: same phone only) It listens on that
  port, registers nowhere, and never looks other nodes up: siblings connect
  to FMutate, not the other way round, so a message to a sibling that has
  gone stays undelivered instead of starting a connection.
  """

  @doc false
  @spec start_link() :: :ignore | {:ok, pid()} | {:error, term()}
  def start_link, do: :ignore

  @doc false
  @spec register_node(atom(), :inet.port_number()) :: {:ok, integer()} | {:error, term()}
  def register_node(_name, _port), do: {:ok, -1}

  @doc false
  @spec register_node(atom(), :inet.port_number(), atom()) :: {:ok, integer()} | {:error, term()}
  def register_node(_name, _port, _family), do: {:ok, -1}

  @doc false
  @spec listen_port_please(atom(), term()) :: {:ok, :inet.port_number()}
  def listen_port_please(_name, _host) do
    case :application.get_env(:kernel, :erl_epmd_node_listen_port) do
      {:ok, port} when is_integer(port) and port > 0 -> {:ok, port}
      _ -> {:ok, 0}
    end
  end

  @doc false
  @spec port_please(atom(), term()) :: term()
  def port_please(_name, _host), do: :noport

  @doc false
  @spec port_please(atom(), term(), timeout()) :: term()
  def port_please(_name, _host, _timeout), do: :noport

  @doc false
  @spec address_please(atom(), term(), atom()) :: term()
  def address_please(_name, host, family), do: :inet.getaddr(host, family)

  @doc false
  @spec names(term()) :: {:ok, list()} | {:error, term()}
  def names(_host), do: {:error, :address}
end
