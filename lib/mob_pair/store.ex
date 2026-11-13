defmodule MobPair.Store do
  @moduledoc """
  Where the joining app keeps its one pairing (`MobPair.Record`): a
  behaviour, implemented by the app over its platform's secure store.

  The record holds the per-app cookie and the joiner's TLS private key, which
  together let a node into the host with full trust: keep it out of backups
  and other devices. Humdinger's implementation is the example: it stores
  `MobPair.Record.to_json/1` under one key with `MobSecureStore`
  (EncryptedSharedPreferences under an Android Keystore master key on
  Android, the Keychain, this device only, on iOS, a 0600 file on a
  computer), reads it back with `MobPair.Record.from_json/1`, and fails
  closed (`{:error, :secure_store_unavailable}`) rather than writing a plain
  file when the platform store is missing.

  A store is `{module, opts}`; `opts` is passed to every callback (e.g. the
  key, so tests can use their own).
  """

  alias MobPair.Record

  @doc """
  The stored pairing, `:none`, or `{:error, reason}` when the store failed or
  the stored value is unreadable (`:corrupt`).
  """
  @callback load(keyword()) :: {:ok, Record.t()} | :none | {:error, term()}

  @doc "Stores the pairing, replacing any other."
  @callback save(Record.t(), keyword()) :: :ok | {:error, term()}

  @doc "Forgets the pairing."
  @callback delete(keyword()) :: :ok | {:error, term()}
end
