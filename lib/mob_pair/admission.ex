defmodule MobPair.Admission do
  @moduledoc false
  # The connection-rate limit of a listener's accept loop (MobPair.Host,
  # MobPair.Front): a global token bucket and one per source address, each
  # `{burst, interval_ms}` (up to `burst` connections at once, then one per
  # `interval_ms`). A connection takes a token from both or is refused before
  # anything is spawned for it. Kept as a GCRA: each bucket is the time it is
  # full again, so a bucket that has refilled is the same as none and can be
  # dropped. At most @max_sources addresses are tracked; past that, new ones
  # are refused until some refill.

  @max_sources 1_024

  @enforce_keys [:rate, :source_rate]
  defstruct [:rate, :source_rate, global: nil, sources: %{}]

  @type rate :: {pos_integer(), pos_integer()}
  @type t :: %__MODULE__{
          rate: rate(),
          source_rate: rate(),
          global: integer() | nil,
          sources: %{:inet.ip_address() => integer()}
        }

  @spec new(rate(), rate()) :: t()
  def new({burst, interval} = rate, {source_burst, source_interval} = source_rate)
      when burst > 0 and interval > 0 and source_burst > 0 and source_interval > 0,
      do: %__MODULE__{rate: rate, source_rate: source_rate}

  @doc "Takes a token for a connection from `ip`, or `:busy`."
  @spec take(t(), :inet.ip_address(), integer()) :: {:ok, t()} | :busy
  def take(admission, ip, now \\ System.monotonic_time(:millisecond)) do
    sources = prune(admission.sources, now)

    with {:ok, source} <- bucket(Map.get(sources, ip), admission.source_rate, now),
         true <- is_map_key(sources, ip) or map_size(sources) < @max_sources,
         {:ok, global} <- bucket(admission.global, admission.rate, now) do
      {:ok, %{admission | global: global, sources: Map.put(sources, ip, source)}}
    else
      _ -> :busy
    end
  end

  # `full_at`: when the bucket is full again (nil: full). A token is free
  # while that is less than a burst's worth of intervals away.
  defp bucket(full_at, {burst, interval}, now) do
    full_at = max(full_at || now, now)
    if full_at - now <= (burst - 1) * interval, do: {:ok, full_at + interval}, else: :busy
  end

  defp prune(sources, _now) when map_size(sources) < @max_sources, do: sources
  defp prune(sources, now), do: Map.reject(sources, fn {_ip, full_at} -> full_at <= now end)
end
