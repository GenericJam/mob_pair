# AGENTS.md: mob_pair

Pairing and Erlang distribution between sibling Mob apps (FMutate, Humdinger, Magpie): QR link,
typed code (SRP-6a), pinned TLS 1.3, per-peer cookies, mDNS. Pure Elixir/OTP; no `mob`
dependency and no native code. This file is for anyone changing the code, human or AI agent.

## Read first

1. [README.md](README.md): what the package does and how an app uses it.
2. [DECISIONS.md](DECISIONS.md): scope, the `service` name, protocol version, the security
   model, platform notes, and what each app needs to adopt it. A change to any of these
   updates DECISIONS.md in the same commit.
3. The protocol: FMutate's `docs/design/protocol.md` §7 and Humdinger's
   `design/fmutate/protocol.md` §1.5–§3 (the wire format, written from this code's origin).

## Toolchain and gate

`.tool-versions` pins Erlang 29 and Elixir 1.20; run mix through mise:

```sh
mise exec -- mix format --check-formatted
mise exec -- mix compile --warnings-as-errors
mise exec -- mix credo --strict
mise exec -- mix test
```

`mix setup` installs the pre-push hook (`.githooks/pre-push`). CI (`.github/workflows/test.yml`)
runs the same gate on Elixir 1.19 / OTP 28; watch it after every push.

## Rules

- **Wire compatibility.** With `service: "fmutate"` the bytes must stay what Humdinger's copy
  sends (`MobPair.Link`, `Srp` labels, `Wire` frames, TXT keys, grant fields). Anything else is
  a protocol version bump (DECISIONS.md §3).
- **Nothing from the network becomes an atom.** Node names and cookies become atoms only after
  the player's Allow (host) or from a validated stored record (joiner).
- **Secrets stay out of logs:** cookies, keys, codes and tokens are redacted from `inspect` and
  `:sys.get_status/1`, and written 0600.
- **Tests** cover what a host or joiner app would notice: boundaries, transitions, errors,
  security refusals. The distribution tests run a real host in a `:peer` node.
- Don't publish to Hex: bumping `version` is Kevin's call.
