defmodule MobPair.Pairings.Store do
  @moduledoc """
  Where `MobPair.Pairings` keeps the host's pairings across restarts
  (`:store` option, `{module, opts}`). The pairings hold the per-app
  cookies, so the store must be private to the host app
  (`MobPair.Pairings.FileStore` writes a 0600 file in app-private storage).

  A revocation must survive a restart: when `save/2` fails after a
  revocation, `Pairings` keeps it in force in memory, deletes the store
  (`delete/1`, optional) rather than leave the revoked pairing on disk, and
  retries `save/2` until it succeeds.
  """

  @doc "The stored pairings (`[]` when none were stored), or an error. Never raises."
  @callback load(keyword()) :: {:ok, [MobPair.Pairings.pairing()]} | {:error, term()}

  @doc "Replaces the stored pairings with `pairings`, durably before it returns `:ok`."
  @callback save([MobPair.Pairings.pairing()], keyword()) :: :ok | {:error, term()}

  @doc "Removes every stored pairing (a missing store is `:ok`); the fallback when `save/2` fails."
  @callback delete(keyword()) :: :ok | {:error, term()}

  @optional_callbacks delete: 1
end
