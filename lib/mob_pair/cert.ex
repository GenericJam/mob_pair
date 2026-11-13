defmodule MobPair.Cert do
  @moduledoc """
  Self-signed TLS certificates for the FMutate link, and their fingerprints.

  Both ends of a pairing identify each other by the SHA-256 of a certificate's
  DER bytes (the `fp`), never by a CA: FMutate's pairing and distribution
  listeners present one self-signed certificate whose `fp` travels in the QR
  code, the link and mDNS; the sibling app makes its own certificate at
  pairing and FMutate pins its `fp` for TLS distribution. The private key
  never leaves the app that made it.

  Keys are ECDSA P-256 and certificates are signed with SHA-256, which every
  TLS 1.3 stack accepts (OTP `ssl` and Android's Conscrypt alike).
  """

  require Record

  @hrl "public_key/include/public_key.hrl"
  for {name, tag} <- [
        tbs: :OTPTBSCertificate,
        signature_algorithm: :SignatureAlgorithm,
        validity: :Validity,
        spki: :OTPSubjectPublicKeyInfo,
        public_key_algorithm: :PublicKeyAlgorithm,
        ec_point: :ECPoint,
        ec_private_key: :ECPrivateKey,
        attribute: :AttributeTypeAndValue
      ] do
    Record.defrecordp(name, tag, Record.extract(tag, from_lib: @hrl))
  end

  @ecdsa_with_sha256 {1, 2, 840, 10_045, 4, 3, 2}
  @ec_public_key {1, 2, 840, 10_045, 2, 1}
  @secp256r1 {1, 2, 840, 10_045, 3, 1, 7}
  @common_name {2, 5, 4, 3}

  @type t :: %{cert: binary(), key: binary(), fp: <<_::256>>}

  @doc """
  A new key pair and a self-signed certificate for `common_name`.

  Returns the certificate's DER, the private key's DER (`ECPrivateKey`) and
  the certificate's fingerprint. Valid from yesterday to the end of 2099:
  peers pin the fingerprint, so expiry would only break a pairing, not
  protect it.
  """
  @spec self_signed(String.t()) :: t()
  def self_signed(common_name) when is_binary(common_name) do
    key = :public_key.generate_key({:namedCurve, @secp256r1})
    name = {:rdnSequence, [[attribute(type: @common_name, value: {:utf8String, common_name})]]}
    from = :calendar.system_time_to_universal_time(System.os_time(:second) - 86_400, :second)

    certificate =
      tbs(
        version: :v3,
        serialNumber: :crypto.strong_rand_bytes(16) |> :binary.decode_unsigned() |> Kernel.+(1),
        signature: signature_algorithm(algorithm: @ecdsa_with_sha256, parameters: :asn1_NOVALUE),
        issuer: name,
        validity:
          validity(notBefore: utc_time(from), notAfter: {:generalTime, ~c"20991231235959Z"}),
        subject: name,
        subjectPublicKeyInfo:
          spki(
            algorithm:
              public_key_algorithm(
                algorithm: @ec_public_key,
                parameters: {:namedCurve, @secp256r1}
              ),
            subjectPublicKey: ec_point(point: ec_private_key(key, :publicKey))
          ),
        issuerUniqueID: :asn1_NOVALUE,
        subjectUniqueID: :asn1_NOVALUE,
        extensions: :asn1_NOVALUE
      )
      |> :public_key.pkix_sign(key)

    %{
      cert: certificate,
      key: :public_key.der_encode(:ECPrivateKey, key),
      fp: fingerprint(certificate)
    }
  end

  @doc "The SHA-256 of a certificate's DER bytes: what peers pin."
  @spec fingerprint(binary()) :: <<_::256>>
  def fingerprint(der) when is_binary(der), do: :crypto.hash(:sha256, der)

  @doc "The `ssl` `certs_keys` entry for a certificate and key made by `self_signed/1`."
  @spec ssl_cert_key(binary(), binary()) :: map()
  def ssl_cert_key(cert, key), do: %{cert: cert, key: {:ECPrivateKey, key}}

  @doc """
  An `ssl` `verify_fun` accepting exactly the certificates whose fingerprint
  `pinned?` accepts (a fingerprint, or a function of one).

  Path validation still runs, so a self-signed certificate reaches the fun as
  `{:bad_cert, :selfsigned_peer}` (or `:unknown_ca`); those are accepted only
  when the fingerprint is pinned. Every other failure (a bad signature, a
  malformed certificate) is fatal. The fun takes the certificate's DER bytes
  (the 4-arity form), so the hash is of exactly what the peer sent.
  """
  @spec verify_fun(<<_::256>> | (<<_::256>> -> boolean())) :: {function(), nil}
  def verify_fun(fp) when is_binary(fp), do: verify_fun(&(&1 == fp))

  def verify_fun(pinned?) when is_function(pinned?, 1) do
    fun = fn
      _otp, der, {:bad_cert, reason}, state when reason in [:selfsigned_peer, :unknown_ca] ->
        pinned(pinned?, der, state)

      _otp, _der, {:bad_cert, reason}, _state ->
        {:fail, reason}

      _otp, _der, {:extension, _}, state ->
        {:unknown, state}

      _otp, der, :valid_peer, state ->
        pinned(pinned?, der, state)

      _otp, _der, :valid, state ->
        {:valid, state}
    end

    {fun, nil}
  end

  defp pinned(pinned?, der, state) do
    if pinned?.(fingerprint(der)), do: {:valid, state}, else: {:fail, :fingerprint_mismatch}
  end

  defp utc_time({{year, month, day}, {hour, minute, second}}) do
    digits =
      [rem(year, 100), month, day, hour, minute, second]
      |> Enum.map_join(&String.pad_leading(Integer.to_string(&1), 2, "0"))

    {:utcTime, String.to_charlist(digits <> "Z")}
  end
end
