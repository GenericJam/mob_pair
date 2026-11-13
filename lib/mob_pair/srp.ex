defmodule MobPair.Srp do
  @moduledoc """
  SRP-6a over the typed pairing code, as both ends of the pairing exchange
  compute it (FMutate's `design/fmutate/protocol.md` §1.5).

  The code is the password: neither side sends it, an eavesdropper learns
  nothing to guess offline, and an active attacker gets one guess per
  attempt (`MobPair.Host` allows five). The proofs bind the session key to the
  certificate fingerprint the sibling saw and to the TLS session (the RFC 9266
  `tls-exporter` channel binding), so a relay that terminates TLS itself
  fails the proofs instead of learning anything.

  Parameters, so another implementation can interoperate (`service` is the
  host's service name, see `MobPair`; FMutate's is `"fmutate"`, so there
  `I = "fmutate"` and the labels are `"fmutate-pair/1 client"` / `server`):

    * group: RFC 5054 2048-bit (`N`), generator `g = 2`;
    * `I = service`, `P` = the code in canonical form (`MobPair.Code`);
    * `x = SHA-256(salt ‖ SHA-256(I ‖ ":" ‖ P))`, `v = g^x mod N`;
    * `k = SHA-1(N ‖ PAD(g))`, `u = SHA-1(PAD(A) ‖ PAD(B))` (RFC 5054);
    * `a`, `b`: 32 random bytes; `A = g^a`, `B = k·v + g^b` (mod `N`);
    * `K = SHA-256(PAD(S))`; `PAD` left-pads with zeros to 256 bytes;
    * `M1 = HMAC-SHA-256(K, "<service>-pair/1 client" ‖ fp ‖ cb ‖ PAD(A) ‖ PAD(B))`,
      `M2 = HMAC-SHA-256(K, "<service>-pair/1 server" ‖ fp ‖ cb ‖ PAD(A) ‖ PAD(B) ‖ M1)`,
      where `fp` is the SHA-256 of the host's certificate (32 bytes) and `cb`
      the 32-byte TLS exporter value for label `EXPORTER-Channel-Binding`
      with an empty context.

  Either side aborts when the other's public value is 0 mod `N` or `u` is 0.
  """

  @n_hex "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
  @n Base.decode16!(@n_hex)
  @n_int :binary.decode_unsigned(@n)
  @g <<2>>
  @width byte_size(@n)
  @version :"6a"

  @doc "The TLS exporter label for the channel binding (RFC 9266)."
  @spec binding_label() :: String.t()
  def binding_label, do: "EXPORTER-Channel-Binding"

  @doc "A fresh 16-byte salt."
  @spec salt() :: binary()
  def salt, do: :crypto.strong_rand_bytes(16)

  @doc "The verifier `v` for a canonical code and salt for `service` (the host's side)."
  @spec verifier(String.t(), binary(), String.t()) :: binary()
  def verifier(code, salt, service), do: :crypto.mod_pow(@g, x(code, salt, service), @n)

  @doc "The client's ephemeral key pair `{A, a}`."
  @spec client_keys() :: {binary(), binary()}
  def client_keys, do: :crypto.generate_key(:srp, {:user, [@g, @n, @version]})

  @doc "The host's ephemeral key pair `{B, b}` for a verifier."
  @spec server_keys(binary()) :: {binary(), binary()}
  def server_keys(verifier), do: :crypto.generate_key(:srp, {:host, [verifier, @g, @n, @version]})

  @doc "Whether a public value from the other side is usable (non-zero mod N)."
  @spec valid_public?(binary()) :: boolean()
  def valid_public?(public) when is_binary(public) and byte_size(public) in 1..@width,
    do: rem(:binary.decode_unsigned(public), @n_int) != 0

  def valid_public?(_), do: false

  @doc "The client's session key `K`, or `:error` for an unusable `B`."
  @spec client_key(String.t(), binary(), {binary(), binary()}, binary(), String.t()) ::
          {:ok, binary()} | :error
  def client_key(code, salt, {a_pub, a_priv}, b_pub, service) do
    with true <- valid_public?(b_pub),
         {:ok, u} <- scrambler(a_pub, b_pub) do
      s =
        :crypto.compute_key(
          :srp,
          b_pub,
          {a_pub, a_priv},
          {:user, [x(code, salt, service), @n, @g, @version, u]}
        )

      {:ok, session_key(s)}
    else
      _ -> :error
    end
  end

  @doc "The host's session key `K`, or `:error` for an unusable `A`."
  @spec server_key(binary(), binary(), {binary(), binary()}) :: {:ok, binary()} | :error
  def server_key(verifier, a_pub, {b_pub, b_priv}) do
    with true <- valid_public?(a_pub),
         {:ok, u} <- scrambler(a_pub, b_pub) do
      s = :crypto.compute_key(:srp, a_pub, {b_pub, b_priv}, {:host, [verifier, @n, @version, u]})
      {:ok, session_key(s)}
    else
      _ -> :error
    end
  end

  @doc "The client's proof `M1`."
  @spec client_proof(binary(), binary(), binary(), binary(), binary(), String.t()) :: binary()
  def client_proof(key, fp, binding, a_pub, b_pub, service) do
    :crypto.mac(:hmac, :sha256, key, [
      service <> "-pair/1 client",
      fp,
      binding,
      pad(a_pub),
      pad(b_pub)
    ])
  end

  @doc "The host's proof `M2`."
  @spec server_proof(binary(), binary(), binary(), binary(), binary(), binary(), String.t()) ::
          binary()
  def server_proof(key, fp, binding, a_pub, b_pub, m1, service) do
    :crypto.mac(:hmac, :sha256, key, [
      service <> "-pair/1 server",
      fp,
      binding,
      pad(a_pub),
      pad(b_pub),
      m1
    ])
  end

  @doc "Constant-time comparison of two proofs or tokens."
  @spec same?(binary(), binary()) :: boolean()
  def same?(a, b) when is_binary(a) and is_binary(b) and byte_size(a) == byte_size(b),
    do: :crypto.hash_equals(a, b)

  def same?(_, _), do: false

  defp x(code, salt, service) do
    inner = :crypto.hash(:sha256, [service, ":", code])
    :crypto.hash(:sha256, [salt, inner])
  end

  defp scrambler(a_pub, b_pub) do
    u = :crypto.hash(:sha, [pad(a_pub), pad(b_pub)])
    if :binary.decode_unsigned(u) == 0, do: :error, else: {:ok, u}
  end

  defp session_key(s), do: :crypto.hash(:sha256, pad(s))

  defp pad(bin) when byte_size(bin) >= @width, do: bin
  defp pad(bin), do: <<0::size((@width - byte_size(bin)) * 8), bin::binary>>
end
