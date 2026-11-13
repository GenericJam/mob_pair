defmodule MobPair.Wire do
  @moduledoc """
  Framing for the pairing exchange (`design/fmutate/protocol.md` §1.5).

  Each message is a JSON object with a `"type"`, sent over TLS 1.3 as one
  frame: a 4-byte big-endian length, then the UTF-8 JSON (`ssl`'s
  `packet: 4`). Frames over 16 KiB are refused by the receiver. Binary
  values are base64url without padding. JSON rather than Erlang terms so
  nothing on the wire can name an atom and any language can implement the
  other end.
  """

  alias MobPair.Srp

  @max_frame 16_384

  @doc "`ssl` options both ends use for the pairing socket."
  @spec socket_options() :: keyword()
  def socket_options do
    [mode: :binary, packet: 4, packet_size: @max_frame, active: false, versions: [:"tlsv1.3"]]
  end

  @doc "Sends one message."
  @spec send(:ssl.sslsocket(), map()) :: :ok | {:error, term()}
  def send(socket, %{"type" => type} = message) when is_binary(type),
    do: :ssl.send(socket, JSON.encode!(message))

  @doc """
  Receives one message: `{:ok, map}` with a string `"type"`, or
  `{:error, :closed | :timeout | :bad_message | term}`.
  """
  @spec recv(:ssl.sslsocket(), timeout()) :: {:ok, map()} | {:error, term()}
  def recv(socket, timeout) do
    with {:ok, frame} <- :ssl.recv(socket, 0, timeout) do
      case JSON.decode(frame) do
        {:ok, %{"type" => type} = message} when is_binary(type) -> {:ok, message}
        _ -> {:error, :bad_message}
      end
    end
  end

  @doc "An `error` message with a reason and optional extra fields."
  @spec error(String.t(), map()) :: map()
  def error(reason, extra \\ %{}), do: Map.merge(extra, %{"type" => "error", "reason" => reason})

  @doc "base64url without padding."
  @spec b64(binary()) :: String.t()
  def b64(bytes), do: Base.url_encode64(bytes, padding: false)

  @doc "Decodes a base64url field; `size` (bytes) checks an exact length, `max` bounds it."
  @spec unb64(term(), keyword()) :: {:ok, binary()} | :error
  def unb64(value, opts \\ [])

  def unb64(value, opts) when is_binary(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, bytes} -> check_size(bytes, opts[:size], opts[:max])
      :error -> :error
    end
  end

  def unb64(_, _), do: :error

  @doc "The 32-byte RFC 9266 channel binding of a TLS 1.3 session."
  @spec channel_binding(:ssl.sslsocket()) :: {:ok, binary()} | {:error, term()}
  def channel_binding(socket) do
    case :ssl.export_key_materials(socket, [Srp.binding_label()], [<<>>], [32]) do
      {:ok, [binding]} -> {:ok, binding}
      {:error, _} = error -> error
    end
  end

  defp check_size(bytes, nil, nil), do: {:ok, bytes}
  defp check_size(bytes, size, nil) when byte_size(bytes) == size, do: {:ok, bytes}
  defp check_size(bytes, nil, max) when byte_size(bytes) <= max, do: {:ok, bytes}
  defp check_size(_, _, _), do: :error
end
