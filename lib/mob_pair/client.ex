defmodule MobPair.Client do
  @moduledoc """
  The joining app's side of the pairing exchange (FMutate's
  `design/fmutate/protocol.md` §1.5): one TLS connection to the host's
  pairing port (`MobPair.Host`), from `hello` to `granted`, returning the
  `MobPair.Record` to keep.

  With a link the certificate is pinned to the link's `fp` before anything is
  sent. With a typed code any certificate is accepted for the TLS handshake,
  and SRP-6a over the code then proves that the peer knows the code and that
  the certificate the joiner saw is the host's own (`MobPair.Srp`).
  """

  alias MobPair.{Cert, Record, Srp, Wire}

  @step_timeout 15_000
  # The user reads the Allow sheet on the host.
  @decision_timeout 180_000

  @type target :: %{
          service: String.t(),
          host: String.t(),
          port: :inet.port_number(),
          inst: String.t(),
          fp: <<_::256>> | nil
        }
  @type auth :: {:token, <<_::128>>} | {:code, MobPair.Code.t()}
  @type identity :: %{
          app_id: String.t(),
          app_name: String.t(),
          device_name: String.t(),
          node: String.t(),
          cert: Cert.t()
        }

  @wire_errors %{
    "unsupported_version" => :unsupported_version,
    "no_such_instance" => :no_such_instance,
    "loopback_only" => :loopback_only,
    "bad_node" => :bad_node,
    "bad_cert" => :bad_cert,
    "not_pairing" => :not_pairing,
    "busy" => :busy,
    "expired" => :expired,
    "invalid_token" => :invalid_token,
    "too_many_attempts" => :too_many_attempts,
    "bad_message" => :bad_message,
    "denied" => :denied,
    "timeout" => :timeout
  }

  @doc """
  Pairs with the host at `target` (`service` names its SRP identity).
  `notify` is called with `:authenticated` once the host has proven itself (and accepted the token or
  code) and `:pending` when it is asking the user.

  Errors: `:unreachable`, `:fingerprint_mismatch` (the certificate isn't the
  link's, or the host's SRP proof doesn't cover the certificate seen),
  `:fingerprint_required` (a token is only ever sent to a pinned host),
  `{:wrong_code, attempts_left}`, `:too_many_attempts`, `:expired`,
  `:invalid_token`, `:not_pairing`, `:busy`, `:denied`, `:timeout`,
  `:loopback_only` (that host has no TLS distribution, so it pairs only
  apps on its own phone), `:bad_node`, `:bad_cert` (the identity's
  certificate is pinned for another node there),
  `:no_such_instance`, `:unsupported_version`, `{:protocol, detail}`.
  """
  @spec pair(target(), auth(), identity(), (atom() -> any())) ::
          {:ok, Record.t()} | {:error, term()}
  def pair(target, auth, identity, notify \\ fn _ -> :ok end)

  # The token is a bearer secret: without the link's fp any listener could take it.
  def pair(%{fp: nil}, {:token, _token}, _identity, _notify), do: {:error, :fingerprint_required}

  def pair(target, auth, identity, notify) do
    with {:ok, socket} <- connect(target) do
      try do
        exchange(socket, target, auth, identity, notify)
      after
        :ssl.close(socket)
      end
    end
  end

  defp connect(%{host: host, port: port, fp: fp}) do
    {:ok, ip} = :inet.parse_strict_address(String.to_charlist(host))
    pinned = if fp, do: Cert.verify_fun(fp), else: Cert.verify_fun(fn _any -> true end)

    options =
      [verify: :verify_peer, cacerts: [], verify_fun: pinned, server_name_indication: :disable] ++
        Wire.socket_options()

    with {:ok, _} <- Application.ensure_all_started(:ssl) do
      ip |> :ssl.connect(port, options, @step_timeout) |> connected(fp)
    end
  end

  defp connected({:ok, socket}, _fp), do: {:ok, socket}

  # Only a pinned connection can fail on the fingerprint.
  defp connected({:error, {:tls_alert, {:handshake_failure, detail}}}, fp) when is_binary(fp) do
    if detail |> to_string() |> String.contains?("fingerprint_mismatch"),
      do: {:error, :fingerprint_mismatch},
      else: {:error, :unreachable}
  end

  defp connected({:error, _}, _fp), do: {:error, :unreachable}

  defp exchange(socket, target, auth, identity, notify) do
    with {:ok, der} <- :ssl.peercert(socket),
         fp = Cert.fingerprint(der),
         :ok <- authenticate(socket, target, fp, auth) do
      notify.(:authenticated)
      :ok = Wire.send(socket, request(identity))
      await_decision(socket, target, fp, identity, notify)
    end
  end

  defp authenticate(socket, target, _fp, {:token, token}) do
    hello = %{
      "type" => "hello",
      "v" => 1,
      "inst" => target.inst,
      "auth" => "token",
      "token" => Wire.b64(token)
    }

    with :ok <- Wire.send(socket, hello) do
      case recv(socket, @step_timeout) do
        {:ok, %{"type" => "welcome"}} -> :ok
        other -> unexpected(other)
      end
    end
  end

  defp authenticate(socket, target, fp, {:code, code}) do
    {a_pub, _} = keys = Srp.client_keys()

    hello = %{
      "type" => "hello",
      "v" => 1,
      "inst" => target.inst,
      "auth" => "srp",
      "A" => Wire.b64(a_pub)
    }

    with :ok <- Wire.send(socket, hello),
         {:ok, %{"type" => "challenge"} = challenge} <- recv(socket, @step_timeout),
         {:ok, salt} <- field(challenge, "salt", max: 64),
         {:ok, b_pub} <- field(challenge, "B", max: 256),
         {:ok, key} <- session_key(code, salt, keys, b_pub, target.service),
         {:ok, binding} <- Wire.channel_binding(socket),
         m1 = Srp.client_proof(key, fp, binding, a_pub, b_pub, target.service),
         :ok <- Wire.send(socket, %{"type" => "proof", "M1" => Wire.b64(m1)}),
         {:ok, %{"type" => "welcome"} = welcome} <- recv(socket, @step_timeout),
         {:ok, m2} <- field(welcome, "M2", size: 32) do
      if Srp.same?(m2, Srp.server_proof(key, fp, binding, a_pub, b_pub, m1, target.service)),
        do: :ok,
        else: {:error, :fingerprint_mismatch}
    else
      other -> unexpected(other)
    end
  end

  defp session_key(code, salt, keys, b_pub, service) do
    case Srp.client_key(code, salt, keys, b_pub, service) do
      {:ok, key} -> {:ok, key}
      :error -> {:error, {:protocol, :bad_public_value}}
    end
  end

  defp request(identity) do
    %{
      "type" => "request",
      "app_id" => identity.app_id,
      "app_name" => identity.app_name,
      "device_name" => identity.device_name,
      "node" => identity.node,
      "client_cert" => Wire.b64(identity.cert.cert),
      "signing_cert_sha256" => nil
    }
  end

  defp await_decision(socket, target, fp, identity, notify) do
    case recv(socket, @decision_timeout) do
      {:ok, %{"type" => "pending"}} ->
        notify.(:pending)
        await_decision(socket, target, fp, identity, notify)

      {:ok, %{"type" => "granted"} = grant} ->
        record(grant, target, fp, identity)

      other ->
        unexpected(other)
    end
  end

  defp record(grant, target, fp, identity) do
    with {:ok, proto} <- Record.dist_proto(grant["dist_proto"]),
         true <- grant["inst"] == target.inst,
         {:ok, record} <-
           Record.validate(%Record{
             service: target.service,
             inst: grant["inst"],
             name: string(grant["name"]),
             device: string(grant["device"]),
             firmware: string(grant["firmware"]),
             node: grant["node"],
             host: grant["dist_host"],
             dist_port: grant["dist_port"],
             dist_proto: proto,
             fp: fp,
             cookie: grant["cookie"],
             self_node: identity.node,
             cert: identity.cert.cert,
             key: identity.cert.key,
             paired_at: System.os_time(:second)
           }) do
      {:ok, record}
    else
      {:error, {:invalid, field}} -> {:error, {:protocol, {:bad_grant, field}}}
      _ -> {:error, {:protocol, :bad_grant}}
    end
  end

  defp recv(socket, timeout) do
    case Wire.recv(socket, timeout) do
      {:ok, %{"type" => "error"} = error} -> {:error, wire_error(error)}
      {:ok, message} -> {:ok, message}
      {:error, :timeout} -> {:error, :timeout}
      {:error, :bad_message} -> {:error, {:protocol, :bad_message}}
      {:error, _closed} -> {:error, {:protocol, :closed}}
    end
  end

  defp wire_error(%{"reason" => "wrong_code"} = error) do
    left = error["attempts_left"]
    {:wrong_code, if(is_integer(left) and left >= 0, do: left)}
  end

  defp wire_error(%{"reason" => reason}) when is_map_key(@wire_errors, reason),
    do: Map.fetch!(@wire_errors, reason)

  defp wire_error(%{"reason" => reason}) when is_binary(reason), do: {:refused, reason}
  defp wire_error(_), do: {:protocol, :bad_message}

  defp field(message, key, opts) do
    case Wire.unb64(message[key], opts) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, {:protocol, {:bad_field, key}}}
    end
  end

  defp unexpected({:error, _} = error), do: error
  defp unexpected({:ok, %{"type" => type}}), do: {:error, {:protocol, {:unexpected, type}}}
  defp unexpected(other), do: {:error, {:protocol, other}}

  defp string(value) when is_binary(value), do: value
  defp string(_), do: nil
end
