defmodule MobPair.Pairings.Store do
  @moduledoc """
  Where `MobPair.Pairings` keeps the host's pairings across restarts
  (`:store` option, `{module, opts}`). The pairings hold the per-app
  cookies, so the store must be private to the host app
  (`MobPair.Pairings.FileStore` writes a 0600 file in app-private storage).
  """

  @doc "The stored pairings (`[]` when none were stored), or an error. Never raises."
  @callback load(keyword()) :: {:ok, [MobPair.Pairings.pairing()]} | {:error, term()}

  @doc "Replaces the stored pairings with `pairings`."
  @callback save([MobPair.Pairings.pairing()], keyword()) :: :ok | {:error, term()}
end
