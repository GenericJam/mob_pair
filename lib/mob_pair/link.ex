defmodule MobPair.Link do
  @moduledoc """
  The pairing link of a host app, the payload of its QR code and of "Copy
  link":

      fmutate://pair?v=1&app=fmutate&inst=a&node=fmutate_a&host=192.168.1.23&port=45123&fp=<b64url>&t=<b64url>

  The scheme is the host's service name (`"fmutate"`, `"magpie"`…, see
  `MobPair`), repeated in `app`. `host` and `port` are the host's pairing
  endpoint (`127.0.0.1` when pasted on the same phone), `fp` the SHA-256 of
  its TLS certificate and `t` the single-use pairing token (128 bits), both
  base64url without padding.

  Parsing is strict: the link comes from a camera or the clipboard, so every
  field is checked and nothing in it becomes an atom. `app` and `inst` may be
  absent (links from hosts that predate them): `app` then defaults to the
  scheme and `inst` to `"a"`.
  """

  @service ~r/\A[a-z][a-z0-9-]{0,31}\z/
  @node ~r/\A[a-z][a-z0-9_]{0,63}\z/

  @typedoc "A parsed link: what `MobPair.Join.pair/3` needs to pair by token."
  @type t :: %{
          via: :link,
          service: String.t(),
          inst: String.t(),
          node: String.t(),
          host: String.t(),
          port: :inet.port_number(),
          fp: <<_::256>>,
          token: <<_::128>>
        }

  @doc "Whether `name` is a valid service name (`~r/\\A[a-z][a-z0-9-]{0,31}\\z/`)."
  @spec service?(term()) :: boolean()
  def service?(name), do: is_binary(name) and Regex.match?(@service, name)

  @doc """
  Parses and validates a link. Surrounding whitespace is ignored (pasted text).

  Options: `:services`, the list of accepted services (default: any valid
  service name).

  Errors: `:not_a_pairing_link` (another scheme or path, an unaccepted
  service, or not a URL), `:unsupported_version`, `{:invalid, field}`,
  `{:missing, field}`.
  """
  @spec parse(String.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def parse(link, opts \\ [])

  def parse(link, opts) when is_binary(link) do
    with {:ok, service, query} <- query(String.trim(link), Keyword.get(opts, :services)),
         :ok <- version(query),
         :ok <- app(query, service),
         {:ok, inst} <- field(Map.put_new(query, "inst", "a"), "inst", :inst, &inst/1),
         {:ok, node} <- field(query, "node", :node, &node_name/1),
         {:ok, host} <- field(query, "host", :host, &ipv4/1),
         {:ok, port} <- field(query, "port", :port, &port/1),
         {:ok, fp} <- field(query, "fp", :fp, &bytes(&1, 32)),
         {:ok, token} <- field(query, "t", :token, &bytes(&1, 16)) do
      {:ok,
       %{
         via: :link,
         service: service,
         inst: inst,
         node: node,
         host: host,
         port: port,
         fp: fp,
         token: token
       }}
    end
  end

  def parse(_, _opts), do: {:error, :not_a_pairing_link}

  @doc "Builds the link a host shows (`MobPair.Host` uses it)."
  @spec build(%{
          service: String.t(),
          inst: String.t(),
          node: String.t(),
          host: String.t(),
          port: :inet.port_number(),
          fp: binary(),
          token: binary()
        }) :: String.t()
  def build(%{service: service, inst: inst, node: node, host: host, port: port, fp: fp, token: t}) do
    query =
      URI.encode_query([
        {"v", "1"},
        {"app", service},
        {"inst", inst},
        {"node", node},
        {"host", host},
        {"port", Integer.to_string(port)},
        {"fp", Base.url_encode64(fp, padding: false)},
        {"t", Base.url_encode64(t, padding: false)}
      ])

    service <> "://pair?" <> query
  end

  defp query(link, services) do
    case URI.new(link) do
      {:ok, %URI{scheme: scheme, host: "pair", path: path, query: query}}
      when is_binary(scheme) and path in [nil, "", "/"] and is_binary(query) ->
        service = String.downcase(scheme)

        if service?(service) and (services == nil or service in services),
          do: {:ok, service, URI.decode_query(query)},
          else: {:error, :not_a_pairing_link}

      _ ->
        {:error, :not_a_pairing_link}
    end
  end

  defp version(%{"v" => "1"}), do: :ok
  defp version(%{"v" => _}), do: {:error, :unsupported_version}
  defp version(_), do: {:error, {:missing, :v}}

  defp app(%{"app" => service}, service), do: :ok
  defp app(%{"app" => _other}, _service), do: {:error, {:invalid, :app}}
  defp app(_query, _service), do: :ok

  defp field(query, key, name, check) do
    case Map.fetch(query, key) do
      {:ok, value} ->
        case check.(value) do
          {:ok, parsed} -> {:ok, parsed}
          :error -> {:error, {:invalid, name}}
        end

      :error ->
        {:error, {:missing, name}}
    end
  end

  # Instances are single lowercase letters ("a" first).
  defp inst(<<c>> = inst) when c in ?a..?z, do: {:ok, inst}
  defp inst(_), do: :error

  defp node_name(name) do
    if Regex.match?(@node, name), do: {:ok, name}, else: :error
  end

  defp ipv4(host) do
    case :inet.parse_strict_address(String.to_charlist(host)) do
      {:ok, {_, _, _, _} = ip} -> {:ok, ip |> :inet.ntoa() |> List.to_string()}
      _ -> :error
    end
  end

  defp port(string) do
    case Integer.parse(string) do
      {port, ""} when port in 1..65_535 -> {:ok, port}
      _ -> :error
    end
  end

  defp bytes(string, size) do
    case Base.url_decode64(string, padding: false) do
      {:ok, bytes} when byte_size(bytes) == size -> {:ok, bytes}
      _ -> :error
    end
  end
end
