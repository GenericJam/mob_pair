defmodule MobPair.Record do
  @moduledoc """
  What the joining app (Humdinger…) keeps from a pairing: where the host app
  (FMutate, Magpie…) is, how to reach it, and the secrets that let it in.

    * `service`: the host's service name (`"fmutate"`, see `MobPair`).
    * `inst`, `name`, `device`, `firmware`: the host's instance id (`"a"`) and
      what the screens show ("FMutate A", "Pixel 7", and the host's detail
      line, for FMutate its firmware name "X0X").
    * `node`: the host's node name, `host` and `dist_port` its distribution
      endpoint (`host` is `"127.0.0.1"` on the same phone; a Wi-Fi address
      follows the host through mDNS), `dist_proto` `:inet_tcp` (loopback) or
      `:inet_tls`; `validate/1` refuses `:inet_tcp` to any other host.
    * `fp`: SHA-256 of the host's TLS certificate, pinned for distribution.
    * `cookie`: the per-app distribution cookie the host generated on Allow.
    * `self_node`: the node name the joiner declared at pairing; the host set
      the cookie for exactly this name, so the joiner keeps it.
    * `cert`, `key`: the joiner's own certificate and private key for TLS
      distribution (made at pairing; the host pins the certificate).

  Node names and cookies are strings here. They become atoms only in
  `MobPair.Transport`, for the one stored pairing, which bounds the atoms a
  peer can make the joiner create.
  """

  alias MobPair.Wire

  # The cookie and the TLS key let a node into the host: keep them out of
  # logs and crash reports.
  @derive {Inspect, except: [:cookie, :key]}
  @enforce_keys [
    :service,
    :inst,
    :node,
    :host,
    :dist_port,
    :dist_proto,
    :fp,
    :cookie,
    :self_node,
    :cert,
    :key
  ]
  defstruct [
    :service,
    :inst,
    :name,
    :device,
    :firmware,
    :node,
    :host,
    :dist_port,
    :dist_proto,
    :fp,
    :cookie,
    :self_node,
    :cert,
    :key,
    :paired_at
  ]

  @type t :: %__MODULE__{
          service: String.t(),
          inst: String.t(),
          name: String.t() | nil,
          device: String.t() | nil,
          firmware: String.t() | nil,
          node: String.t(),
          host: String.t(),
          dist_port: :inet.port_number(),
          dist_proto: :inet_tcp | :inet_tls,
          fp: <<_::256>>,
          cookie: String.t(),
          self_node: String.t(),
          cert: binary(),
          key: binary(),
          paired_at: integer() | nil
        }

  @self_node ~r/\A[a-z][a-z0-9_]{0,63}@[A-Za-z0-9.\-]{1,253}\z/
  @cookie ~r/\A[A-Za-z0-9_\-]{32,128}\z/

  @doc "Whether `name` is a well-formed host node name (`short@host`)."
  @spec host_node?(term()) :: boolean()
  def host_node?(name), do: self_node?(name)

  @doc "Whether `name` is a well-formed node name for the joiner itself (`short@host`)."
  @spec self_node?(term()) :: boolean()
  def self_node?(name), do: is_binary(name) and Regex.match?(@self_node, name)

  @doc "Whether `cookie` is a well-formed per-app cookie (base64url, 32–128 chars)."
  @spec cookie?(term()) :: boolean()
  def cookie?(cookie), do: is_binary(cookie) and Regex.match?(@cookie, cookie)

  @doc "Whether `host` is a dotted IPv4 address."
  @spec ipv4?(term()) :: boolean()
  def ipv4?(host) when is_binary(host),
    do: match?({:ok, {_, _, _, _}}, :inet.parse_strict_address(String.to_charlist(host)))

  def ipv4?(_), do: false

  @doc "Whether the record (or a dotted IPv4 host) points at the host on this phone."
  @spec loopback?(t() | String.t()) :: boolean()
  def loopback?(%__MODULE__{host: host}), do: loopback?(host)
  def loopback?(host) when is_binary(host), do: match?({:ok, {127, _, _, _}}, parse(host))

  @doc """
  Whether `host` is an address a host app on another phone can have: dotted
  IPv4, unicast, not loopback, not unspecified. What mDNS says is checked
  with this before the link follows it.
  """
  @spec remote_unicast?(term()) :: boolean()
  def remote_unicast?(host) when is_binary(host) do
    case parse(host) do
      {:ok, {a, _, _, _}} when a in [0, 127] or a >= 224 -> false
      {:ok, {_, _, _, _}} -> true
      _ -> false
    end
  end

  def remote_unicast?(_), do: false

  defp parse(host), do: :inet.parse_strict_address(String.to_charlist(host))

  @doc "Validates a record built from a grant or loaded from storage."
  @spec validate(t()) :: {:ok, t()} | {:error, {:invalid, atom()}}
  def validate(%__MODULE__{} = record) do
    checks = [
      service: MobPair.Link.service?(record.service),
      inst: match?(<<c>> when c in ?a..?z, record.inst),
      node: host_node?(record.node),
      host: ipv4?(record.host),
      dist_port: is_integer(record.dist_port) and record.dist_port in 1..65_535,
      dist_proto: carrier?(record.dist_proto, record.host),
      fp: is_binary(record.fp) and byte_size(record.fp) == 32,
      cookie: cookie?(record.cookie),
      self_node: self_node?(record.self_node),
      cert: is_binary(record.cert) and record.cert != "",
      key: is_binary(record.key) and record.key != ""
    ]

    case Enum.find(checks, fn {_, ok?} -> not ok? end) do
      nil -> {:ok, record}
      {field, false} -> {:error, {:invalid, field}}
    end
  end

  # Plain distribution has no integrity after the handshake: loopback only.
  defp carrier?(:inet_tls, _host), do: true
  defp carrier?(:inet_tcp, host) when is_binary(host), do: loopback?(host)
  defp carrier?(_proto, _host), do: false

  @doc "The record as JSON, for the secure store."
  @spec to_json(t()) :: String.t()
  def to_json(%__MODULE__{} = r) do
    JSON.encode!(%{
      "v" => 1,
      "service" => r.service,
      "inst" => r.inst,
      "name" => r.name,
      "device" => r.device,
      "firmware" => r.firmware,
      "node" => r.node,
      "host" => r.host,
      "dist_port" => r.dist_port,
      "dist_proto" => Atom.to_string(r.dist_proto),
      "fp" => Wire.b64(r.fp),
      "cookie" => r.cookie,
      "self_node" => r.self_node,
      "cert" => Wire.b64(r.cert),
      "key" => Wire.b64(r.key),
      "paired_at" => r.paired_at
    })
  end

  @doc "Reads a record written by `to_json/1`; anything else is an error, never a crash."
  @spec from_json(binary()) :: {:ok, t()} | {:error, term()}
  def from_json(json) when is_binary(json) do
    with {:ok, %{"v" => 1} = m} <- JSON.decode(json),
         {:ok, proto} <- dist_proto(m["dist_proto"]),
         {:ok, fp} <- Wire.unb64(m["fp"], size: 32),
         {:ok, cert} <- Wire.unb64(m["cert"]),
         {:ok, key} <- Wire.unb64(m["key"]) do
      validate(%__MODULE__{
        # Records stored before the service existed are FMutate's.
        service: Map.get(m, "service", "fmutate"),
        inst: m["inst"],
        name: string_or_nil(m["name"]),
        device: string_or_nil(m["device"]),
        firmware: string_or_nil(m["firmware"]),
        node: m["node"],
        host: m["host"],
        dist_port: m["dist_port"],
        dist_proto: proto,
        fp: fp,
        cookie: m["cookie"],
        self_node: m["self_node"],
        cert: cert,
        key: key,
        paired_at: if(is_integer(m["paired_at"]), do: m["paired_at"])
      })
    else
      _ -> {:error, :corrupt}
    end
  end

  @doc ~s[Maps a wire `dist_proto` (`"inet_tcp"` / `"inet_tls"`) to its atom.]
  @spec dist_proto(term()) :: {:ok, :inet_tcp | :inet_tls} | :error
  def dist_proto("inet_tcp"), do: {:ok, :inet_tcp}
  def dist_proto("inet_tls"), do: {:ok, :inet_tls}
  def dist_proto(_), do: :error

  defp string_or_nil(value) when is_binary(value), do: value
  defp string_or_nil(_), do: nil
end
