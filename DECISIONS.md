# mob_pair: decisions

Pairing and Erlang distribution between sibling Mob apps (FMutate, Humdinger, Magpie, ...),
built once. Protocol: FMutate's `protocol.md` §1 (pairing), §2 (transport), §3 (trust), as
written in `humdinger/design/fmutate/protocol.md` §1.5, and Magpie's `design/protocol.md` §1
("build it once as a shared module"). This file records what the package decided and why.

## 1. Scope

**In the package** (pure OTP `ssl`/`public_key`/`crypto` and Elixir 1.18 `JSON`; no `mob`, no
native code, so it runs the same on Android, iOS and a host, and tests run anywhere):

| Concern | Module | Side |
|---|---|---|
| Typed code (8 Crockford chars) | `MobPair.Code` | both |
| QR / link payload | `MobPair.Link` | both |
| Self-signed certificates, pinning `verify_fun` | `MobPair.Cert` | both |
| Pairing frames (4-byte length + JSON over TLS 1.3) | `MobPair.Wire` | both |
| SRP-6a over the typed code, bound to `fp` and the TLS session | `MobPair.Srp` | both |
| Pairing endpoint: secret, attempts, Allow hook, grant | `MobPair.Host` | host |
| Paired peers: per-peer cookies, pinned client certs, revocation | `MobPair.Pairings` (+ `Pairings.Store`, `Pairings.FileStore`) | host |
| TLS distribution for a node started at runtime on plain loopback | `MobPair.Front` | host |
| Fixed-port, no-epmd port mapper for a host booted with `-epmd_module` | `MobPair.FixedEpmd`, `MobPair.boot_args/1` | host |
| mDNS responder (advertise) | `MobPair.Responder` | host |
| One pairing exchange | `MobPair.Client` | joiner |
| A Pair screen's service (link, typed code + mDNS candidates) | `MobPair.Join` | joiner |
| mDNS browse (one-shot legacy unicast) | `MobPair.Discovery`, `MobPair.Dns` | joiner |
| What a joiner keeps, validated | `MobPair.Record` (+ `MobPair.Store` behaviour) | joiner |
| Joiner's node, route, connect/revoke | `MobPair.Transport`, `MobPair.Epmd`, `MobPair.Tunnel` | joiner |

**Stays in each app:** screens, styles and copy (QR rendering, the Allow sheet, error
states), the approval UX, where secrets are stored (the `Store` behaviours: Humdinger uses
`mob_secure_store`, FMutate a 0600 app-private file), the app's message facade (FMutate's
`:fmutate_instance`, Magpie's `{:magpie, 1, ...}`), how the app's node is started and
admitted (FMutate's `FMutate.Dist`), and platform-only pieces (Android `NsdManager`, the
content-provider cookie handover, iOS Local Network prompts).

Every app is both a possible host ("My code") and joiner ("Scan"); the package doesn't force
either.

## 2. The `service` name

One lowercase name per host family, e.g. `"fmutate"`, `"magpie"`, selects:

- the link scheme and `app` field: `<service>://pair?v=1&app=<service>&inst=…`;
- the mDNS type `_<service>._tcp.local`;
- SRP's identity `I = service` and proof labels `"<service>-pair/1 client|server"`, so a
  proof for one family never verifies for another;
- the reserved node prefix: a host refuses its own node name and `<service>_*` (`bad_node`).

With `service: "fmutate"` the bytes on the wire are exactly what Humdinger implements today
(the only addition is the `app=fmutate` link field, which Humdinger's parser ignores).

## 3. Protocol version

`v=1` everywhere (link, hello, TXT, stored records). A host answers any other `v` with
`unsupported_version`; a joiner refuses a link with another `v`. A future v2 adds fields
rather than changing v1's; JSON keeps both ends free of atoms from the network.

## 4. Security model

- **Distribution is full trust**, both ways. Everything below decides who gets a connection;
  nothing limits what a connected node can do (protocol §3).
- **Host identity:** one long-lived self-signed ECDSA P-256 certificate; `fp` = SHA-256 of its
  DER. The QR/link carries `fp` out of band, so a joiner pins it before sending anything.
  A typed code carries no `fp`; SRP-6a proves it instead (below).
- **Single-use secret** per open Pair screen: a 40-bit code and a 128-bit token, valid 5 min,
  5 failed attempts (wrong token or wrong SRP proof alike) kill both until New code. A
  successful authentication uses the secret up, whatever the player decides. Tokens and proofs
  are compared in constant time. At most 8 pairing connections are served at once, and the
  SRP verifier is computed in the connection's process, not the one holding the secret.
- **SRP-6a** (RFC 5054 2048-bit group, SHA-256 `x`, `K = SHA-256(PAD(S))`): the code is never
  sent; `M1`/`M2` are HMACs over the certificate the joiner saw and the RFC 9266 TLS exporter,
  so a relay that terminates TLS fails the proofs and gets one online guess per attempt.
- **TLS 1.3 only**, everywhere (pairing, `Front`, `Tunnel`, `-ssl_dist_optfile`).
- **Allow:** nothing connects without the host player's Allow. Names in the request
  (`app_name`, `device_name`) are what the joiner claims: control and format characters are
  stripped, and a host shows a request from another address as "says it is …". A request that
  would replace an existing pairing under the same node name with another certificate says so.
- **Grant:** a per-peer cookie (32 random bytes, base64url) set for exactly the node name the
  joiner declared (the atom is made only after Allow), and the joiner's own certificate pinned
  (its key never leaves the joiner). Revoking (Disconnect, or the joiner's `unpair`)
  disconnects, replaces the cookie with a random one and unpins the certificate.
- **Carriers:** plain `inet_tcp` only on loopback (the host's listener bound to 127.0.0.1);
  a joiner on another address is always granted `inet_tls` (mutual TLS 1.3, both certificates
  pinned). `Record.validate/1` and `Transport.connect/2` refuse plain distribution to a
  non-loopback host. A host without TLS distribution answers `loopback_only` before an
  attempt is spent.
- **`Front`** binds a pinned client certificate to its paired node name: the first
  distribution handshake message must declare that name, so one pairing's certificate can't
  be used under another pairing's name (the cookie check then still applies).
- **mDNS is unauthenticated:** answers only produce candidates to *try* (pinned TLS + cookie
  decide); a reply is accepted only with one of the query's ids, and records are kept per
  reply source, so a forged reply is a second candidate, never a replacement.
- **Atoms:** node names and cookies become atoms only from an approved pairing or a validated
  stored record, never from pairing or mDNS input.
- **Secrets at rest:** cookies and private keys are hidden from `inspect` (`Record`) and from
  `:sys.get_status/1` (`Host`), and written 0600 via a temporary file and rename
  (`Pairings.FileStore`, `-ssl_dist_optfile`). Where the platform has a hardware-backed store,
  apps should prefer it (`MobPair.Store` / `Pairings.Store` are behaviours for that).

## 5. Node names and addresses

A node name is a label, not an address: the joiner routes the host's node to `{dist_host,
dist_port}` (`MobPair.Epmd`), so no epmd runs on either side and nothing resolves names.
Joiners declare `<app>_<random>@127.0.0.1` (unique per pairing). Hosts keep their own fixed
name: FMutate is always `fmutate_a@127.0.0.1`, even for a joiner on another phone. When mDNS
reports a new address, a joiner must change the route and keep the granted node name
(Humdinger's link currently rewrites the host part, which only works for hosts named after
their IP; see "Adopting").

## 6. Hosts whose distribution starts at runtime (`Front`)

`-proto_dist` is read at boot, and Mob apps start distribution at runtime (Android: a few
seconds after launch), so a Mob host can't simply run `inet_tls_dist`. It keeps its plain
loopback listener (same-phone peers, development tools) and runs `MobPair.Front` on the Wi-Fi
address only while at least one `inet_tls` pairing exists: TLS 1.3 with the host certificate,
pinned client certificates, the name check above, then the handshake reframed from 4-byte to
2-byte lengths (and back) and forwarded to the loopback listener. The node sees an ordinary
loopback connection under the paired name and checks its cookie. A host booted with stock
`-proto_dist inet_tls` and `Pairings.write_ssl_dist_optfile/2` needs no `Front`; joiners
can't tell the difference.

## 7. Platforms

- **Android:** `ssl`, `public_key`, `crypto` and `asn1` must stay in a release bundle
  (`extra_applications`). The system mDNS responder owns UDP 5353; `MobPair.Responder` tries
  to share it (`reuseaddr`/`reuseport`) and a `Host` keeps running without mDNS if it can't
  bind (the QR/link path needs no mDNS; the typed code does). A robust advertiser on Android
  is `NsdManager` (native, per app); receiving multicast may need a `WifiManager.MulticastLock`.
  Joiners browse with legacy unicast and need neither. Listening needs `INTERNET`.
  FMutate's same-key content provider (`com.genericjam.fmutate.siblings`) is Android-only and
  outside the package.
- **iOS:** listening for or connecting to LAN peers triggers the Local Network prompt; an app
  needs `NSLocalNetworkUsageDescription` and `NSBonjourServices` (`_<service>._tcp`) in
  Info.plist. Apps can't share a loopback between them on iOS the way Android apps can, so the
  "same phone" path is Android-only in practice; another iPhone or Android phone pairs over
  Wi-Fi. Nothing in the package is platform-specific.
- **Host (Mac/Linux):** everything runs; tests run the host side in a `:peer` node. A process
  started from an agent terminal on macOS can't use LAN multicast (Local Network privacy).

## 8. Adopting

- **FMutate** (first host): `FMutate.Pairing` + `FMutate.PairScreen`; `FMutate.Dist` follows
  `MobPair.Pairings` (`default_cookie: :keep, allow_list: false` since `FMutate.Dist` owns
  the default cookie and admission).
- **Humdinger** (joiner today, its own copies): replace `Humdinger.FMutate.{Code, PairLink,
  Cert, Wire, Srp, Record, Pairing.Client, Pairing, Discovery, Dns, Epmd, Tunnel, Transport}`
  and `Reference.*` with the package (`service: "fmutate"`); keep `Humdinger.FMutate` (the
  link), its `Store` (mob_secure_store) and its screens; route a moved FMutate by address and
  keep the granted node name (§5); stored records without `service` load as `"fmutate"`.
- **Magpie** (host and joiner): `service: "magpie"` for its own Pair screen; `MobPair.Join`
  with `service: "fmutate"` to pair with FMutate.
