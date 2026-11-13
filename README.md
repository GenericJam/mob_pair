# mob_pair

Pairing and Erlang distribution between sibling [Mob](https://hexdocs.pm/mob) apps, on one
phone or across phones on the same Wi-Fi. A **host** app (FMutate, Magpie) shows a QR code and
an 8-character code; a **joining** app (Humdinger, Magpie) scans or types it, the host's player
taps Allow, and the joiner connects to the host's node with a cookie of its own: over loopback
on the same phone, over mutual TLS 1.3 with both certificates pinned from another phone.

Pure Elixir/OTP (`ssl`, `public_key`, `crypto`); no native code, no `mob` dependency.
[DECISIONS.md](DECISIONS.md) has the scope, the security model and the platform notes.

```elixir
# mix.exs (not on Hex yet)
{:mob_pair, github: "GenericJam/mob_pair", ref: "<commit>"}
```

## Host ("My code")

```elixir
# once, with the app's other processes (the store keeps cookies and pinned certificates)
{MobPair.Pairings, store: {MobPair.Pairings.FileStore, path: Path.join(data_dir, "pairings.json")}}

# while the Pair screen is open
{:ok, host} =
  MobPair.Host.start_link(
    service: "fmutate",              # link scheme, mDNS type, SRP labels, reserved node prefix
    cert: cert,                      # MobPair.Cert.self_signed("FMutate"), made once and kept
    node: Atom.to_string(node()),
    host: wifi_ip,                   # the address in the QR code
    dist_port: tls_port,             # what another phone is granted (always inet_tls)
    loopback_dist: %{port: 9150, proto: :inet_tcp},   # what this phone is granted
    approve: {:ask, self()},         # {:mob_pair_request, host, ref, request} → MobPair.Host.decide/3
    notify: self(),                  # {:mob_pair_secret, host, status}
    advertise: []                    # mDNS (_fmutate._tcp), best effort
  )

MobPair.Host.info(host)
#=> %{code: "KQ7M-X2PD", link: "fmutate://pair?v=1&app=fmutate&inst=a&...", status: :open,
#     attempts_left: 5, expires_in: 299_000, port: 50_123, advertising: true}
```

A node started at runtime on plain loopback distribution (a Mob app) serves other phones
through `MobPair.Front` (TLS 1.3, pinned client certificates, paired names checked, forwarded
to the loopback listener). A node booted with `MobPair.boot_args/1` and
`MobPair.Pairings.write_ssl_dist_optfile/2` runs stock `inet_tls` instead.

## Joiner ("Scan")

```elixir
{:ok, _} =
  MobPair.Join.start_link(
    service: "fmutate",
    app_id: "com.genericjam.humdinger",
    app_name: "Humdinger",
    device_name: "Pixel 7",
    self_node: fn -> MobPair.Transport.random_node_name("humdinger") end,
    install: fn record -> MyApp.Store.save(record) end   # a MobPair.Record: keep it secret
  )

{:ok, link} = MobPair.Join.parse_link(scanned)
:ok = MobPair.Join.pair(self(), link)               # or %{code: "KQ7M-X2PD"} (mDNS + SRP-6a)
# → {:mob_pair, :matched, candidate}, {:mob_pair, :waiting}, {:mob_pair, :paired, info}
#   or {:mob_pair, :failed, reason}

:ok = MobPair.Transport.setup()                      # before distribution starts
{:ok, conn} = MobPair.Transport.connect(record, self())
send({:fmutate_instance, conn.node}, ...)            # the host's own message protocol
```

## Development

```sh
mise exec -- mix test     # includes a real host in a :peer node: loopback, TLS, the front
```

See [AGENTS.md](AGENTS.md).
