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
  are compared in constant time. An SRP proof counts only against the secret it was computed
  for: New code turns an exchange already under way into `expired`. The SRP verifier is
  computed in the connection's process, not the one holding the secret. A token is only ever
  sent to a pinned host (`Client.pair/4` refuses a token without `fp`).
- **Where the endpoint listens:** loopback (apps on this phone) and the address in the link
  (Wi-Fi), on one port; never `0.0.0.0`, so mobile data, VPN and tethering never see the
  pre-auth surface. `Front` has no default address: `:ip` is required (a wildcard only if the
  caller passes one). Admission, in the acceptor before any process or TLS handshake: at most
  8 connections before authentication, 2 per source address, and token buckets on accepted
  connections (`:accept_rate`, 40 then 1 per 100 ms, and `:accept_rate_per_source`, 10 then 1
  a second); an over-limit socket is closed at once. 10 s for the TLS handshake. An SRP
  challenge the joiner leaves without a proof (hangs up, sends garbage) counts as a failed
  attempt, so repeated TLS + `A` + disconnect can't make the host compute verifiers for free.
  (Anyone who reaches the port can still burn the 5 attempts: New code.) `Front` has the same
  pre-auth limits, counted apart from its forwarded connections, so a peer without a pinned
  certificate can't crowd out paired siblings. Stopping a `Host` (the Pair screen closes)
  closes the connections in progress and withdraws their requests (`{:mob_pair_withdrawn,
  host, ref}`).
- **SRP-6a** (RFC 5054 2048-bit group, SHA-256 `x`, `K = SHA-256(PAD(S))`): the code is never
  sent; `M1`/`M2` are HMACs over the certificate the joiner saw and the RFC 9266 TLS exporter,
  so a relay that terminates TLS fails the proofs and gets one online guess per attempt.
- **TLS 1.3 only**, everywhere (pairing, `Front`, `Tunnel`, `-ssl_dist_optfile`).
- **Allow:** nothing connects without the host player's Allow. Every name in the request
  (`app_name`, `device_name`, the node) is a claim, from this phone or another: control,
  format, line/paragraph-separator, private-use and unassigned characters are stripped and
  spaces collapsed; hosts should word the sheet as "an app … says it is …" either way (another
  app on the same phone can know the secret too, e.g. from the clipboard). A request that
  would replace an existing pairing under the same node name says so (whatever its
  certificate); the host's own name, `<service>_*`, names the app reserves (`:reserved`, e.g.
  FMutate's same-key siblings) and names over 255 bytes are refused before Allow.
- **Grant:** a per-peer cookie (32 random bytes, base64url) set for exactly the node name the
  joiner declared (the atom is made only after Allow), and the joiner's own certificate pinned
  (its key never leaves the joiner; the request doesn't prove possession, so a certificate
  already pinned for another node is refused: `bad_cert` at the request, and
  `Pairings.add/1` refuses it too). A replaced pairing is revoked first.
- **Revoke** (Disconnect, the joiner's `unpair`, a replacement): the cookie is replaced with a
  random one first, a handshake of that node already under way is aborted (`net_kernel`'s
  disconnect leaves pending connections alone, and `dist_util` reads the cookie when it marks
  the connection pending), the connection is cut, then a handshake that was parked behind it
  (`up_pending`, which the disconnect turns into `pending`) is aborted too, and the certificate
  is unpinned. For twice `net_setuptime` after a revoke, a connection of that name that still
  comes up is dropped at `nodeup`; after that the name may come back another way (FMutate's
  same-key Allow). Revoking can't undo what a connected node already did: distribution is
  full trust.
- **Persistence fails closed.** `add/1` grants nothing unless the store saved it
  (`{:error, {:store, reason}}`; the Host answers `busy`). `revoke/1` takes effect in the VM at
  once and returns `:ok` only once the store no longer holds the pairing; if the save fails it
  returns `{:error, {:store, reason}}`, deletes the store (`Store.delete/1`) so the revoked
  pairing can't come back at the next start (the others then need pairing again if the app
  restarts before the store recovers), and retries the save (1 s doubling to a minute;
  `saved?/0` tells the app). If the store can't be deleted either, a restart inside that window
  can bring the revoked pairing back; nothing in Erlang can do better. Files are written to a
  synced temporary file and renamed; the directory entry isn't synced (Erlang can't open a
  directory to fsync it), so a power cut right after a write can bring the previous file back.
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
  reply source IP (the port doesn't count), at most 4 instances per source, so a forged reply
  is a second candidate, never a replacement, and one machine can't crowd out another. A typed
  code is tried against at most 8 candidates, unicast IPv4 or loopback only, round-robin
  across sources in random order; a candidate that fails before it authenticated
  (`fingerprint_mismatch`, a bad proof, a timeout) doesn't stop the search. Both UDP sockets
  read `active: :once` with a per-window packet budget (the excess waits in, or is dropped by,
  the kernel), and the responder sends at most `:max_replies` a second. `Host` advertises only
  on its link's interface (`Responder` `:interface`): it joins the group there and treats only
  that subnet as on-link; a responder that stops leaves the Host running.
- **Atoms:** node names and cookies become atoms only from an approved pairing or a validated
  stored record, never from pairing or mDNS input; `Pairings.add/1`, `Transport.connect/2`
  (`Record.validate/1`) and `Transport.start_node/1` check what they atomize whoever calls
  them. On the host's node, OTP's distribution handshake makes an atom of every name a
  connecting node declares before it checks the cookie, unless the `net_kernel` allow list
  refuses the name first; an empty allow list allows everything. So `allow_list: :auto`
  (default) sets a placeholder name plus the paired names right after distribution starts,
  and any other name is refused with no atom made. A host that turns it off (`false`) must keep
  its own non-empty allow list, or anyone who reaches its listener (any app on an Android phone,
  for a loopback listener) can fill the atom table. The few connections accepted between
  `Node.start/2` and the first `allow/1` are the only window.
- **Secrets at rest:** cookies and private keys are hidden from `inspect` (`Record`) and from
  `:sys.get_status/1` (`Host`, `Front`: their TLS options carry the key too), and
  written 0600 inside a fresh 0700 directory, fsynced, then renamed into place
  (`Pairings.write_private/2`: `Pairings.FileStore`, `-ssl_dist_optfile`). Where the platform
  has a hardware-backed store, apps should prefer it (`MobPair.Store` / `Pairings.Store` are
  behaviours for that). The pairing maps (`Pairings.list/0`, subscriber messages) carry the
  cookie: don't log them.

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

Cookies, the default cookie and the allow list belong to the running node, so such a host
starts `MobPair.Pairings` with its other processes and calls
`MobPair.Pairings.distribution_started/0` once `Node.start/2` returned (and after any
restart of distribution); until then paired siblings can't connect, which an adopter notices
at once.

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
  `MobPair.Pairings` (`default_cookie: :keep` since `FMutate.Dist` owns the default cookie;
  `allow_list: :auto` in release builds, `false` only in builds deployed by mob_dev, whose
  tools connect under names chosen per run) and calls `distribution_started/0`. Same-key
  siblings register their node name through FMutate's content provider before they connect
  (FMutate protocol.md §7), and FMutate adds the name to the allow list only when the player
  allows it; those names are `:reserved`. Copy link copies `Host.local_link/1` (host
  127.0.0.1). Disconnect shows `revoke/1`'s store error and `saved?/0`.
- **Humdinger** (joiner today, its own copies): replace `Humdinger.FMutate.{Code, PairLink,
  Cert, Wire, Srp, Record, Pairing.Client, Pairing, Discovery, Dns, Epmd, Tunnel, Transport}`
  and `Reference.*` with the package (`service: "fmutate"`); keep `Humdinger.FMutate` (the
  link), its `Store` (mob_secure_store) and its screens; route a moved FMutate by address and
  keep the granted node name (§5); stored records without `service` load as `"fmutate"`.
- **Magpie** (host and joiner): `service: "magpie"` for its own Pair screen; `MobPair.Join`
  with `service: "fmutate"` to pair with FMutate.
