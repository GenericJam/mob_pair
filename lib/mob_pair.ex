defmodule MobPair do
  @moduledoc """
  Pairing and Erlang distribution between sibling Mob apps on one phone or
  across phones: a host app (FMutate, Magpie…) shows a QR link and a typed
  code; a joining app (Humdinger…) pairs with it and then connects to the
  host's node with a per-app cookie, over loopback or pinned TLS 1.3.

  Every host has a `service` name, `~r/\\A[a-z][a-z0-9-]{0,31}\\z/` (FMutate's
  is `"fmutate"`). It is the link scheme (`fmutate://pair?…`), the mDNS
  service type (`_fmutate._tcp.local`), the SRP identity and proof labels,
  and the reserved node prefix (`fmutate_*` names are the host's).

  ## Host side

    * `boot_args/1`: the host node's boot arguments (no epmd, a fixed port,
      `MobPair.FixedEpmd`).
    * `MobPair.Pairings`: paired siblings, per-app cookies, pinned client
      certificates, revocation; persisted with `MobPair.Pairings.Store`
      (`MobPair.Pairings.FileStore`).
    * `MobPair.Host`: the pairing endpoint behind the "Pair an app" screen
      (code, link, SRP, Allow, grant), advertised with `MobPair.Responder`.
    * `MobPair.Front`: TLS distribution for a host whose node runs plain
      `inet_tcp` on loopback because it started at runtime (a Mob app):
      pinned client certificates, the paired node name checked, then
      forwarded to the loopback listener.

  ## Joining side

    * `MobPair.Join`: the service behind the Pair screen (link, typed code,
      discovery with `MobPair.Discovery`), running `MobPair.Client`.
    * `MobPair.Record`: the stored pairing, kept by the app's
      `MobPair.Store`.
    * `MobPair.Transport`: the joiner's node and the connection, routed by
      `MobPair.Epmd`, through `MobPair.Tunnel` for TLS distribution.

  ## Both

  `MobPair.Code`, `MobPair.Link`, `MobPair.Srp`, `MobPair.Wire`,
  `MobPair.Cert`, `MobPair.Dns`.
  """

  @doc """
  The host's boot arguments (strings, for `erl`, `:peer` or `Mob.InitArgs`):
  no epmd, a fixed port, and either TLS distribution (`-proto_dist
  inet_tls`, the only carrier a sibling on another phone is granted) or
  plain distribution bound to loopback (same phone only). Plain
  distribution has no integrity after the cookie handshake, so it must
  never listen on Wi-Fi.

  Options: `:dist_port` (required), `:dist_proto` (`:inet_tls`, the default,
  with `:ssl_dist_optfile` from `MobPair.Pairings.write_ssl_dist_optfile/2`;
  or `:inet_tcp`, which binds the listener to 127.0.0.1).
  """
  @spec boot_args(keyword()) :: [String.t()]
  def boot_args(opts) do
    port = Keyword.fetch!(opts, :dist_port)

    base = [
      "-start_epmd",
      "false",
      "-epmd_module",
      Atom.to_string(MobPair.FixedEpmd),
      "-kernel",
      "erl_epmd_node_listen_port",
      Integer.to_string(port)
    ]

    case Keyword.get(opts, :dist_proto, :inet_tls) do
      :inet_tls ->
        base ++
          [
            "-proto_dist",
            "inet_tls",
            "-ssl_dist_optfile",
            Keyword.fetch!(opts, :ssl_dist_optfile)
          ]

      :inet_tcp ->
        base ++ ["-kernel", "inet_dist_use_interface", "{127,0,0,1}"]
    end
  end
end
