defmodule MobPair.Pairings.FileStore do
  @moduledoc """
  `MobPair.Pairings.Store` as a JSON file at `opts[:path]`, written 0600 via
  a temporary file and a rename (`MobPair.Pairings.write_private/2`), so a
  crash mid-write leaves the previous list. A missing file is no pairings;
  an unreadable one is `{:error, :corrupt}`, never a crash.

      {"v": 1, "pairings": [{"node": "humdinger_x@127.0.0.1", "app_id": …,
        "app_name": …, "device_name": …, "client_fp": "<b64url>",
        "dist_proto": "inet_tls", "cookie": …, "paired_at": 1790000000}]}
  """

  @behaviour MobPair.Pairings.Store

  alias MobPair.{Pairings, Record, Wire}

  @impl true
  def load(opts) do
    case File.read(Keyword.fetch!(opts, :path)) do
      {:ok, json} -> decode(json)
      {:error, :enoent} -> {:ok, []}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def save(pairings, opts) do
    json = JSON.encode!(%{"v" => 1, "pairings" => Enum.map(pairings, &encode/1)})
    Pairings.write_private(Keyword.fetch!(opts, :path), json)
  end

  @impl true
  def delete(opts) do
    case File.rm(Keyword.fetch!(opts, :path)) do
      :ok -> :ok
      {:error, :enoent} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp encode(p) do
    %{
      "node" => p.node,
      "app_id" => p.app_id,
      "app_name" => p.app_name,
      "device_name" => p.device_name,
      "client_fp" => Wire.b64(p.client_fp),
      "dist_proto" => if(p[:dist_proto], do: Atom.to_string(p.dist_proto)),
      "cookie" => p.cookie,
      "paired_at" => p.paired_at
    }
  end

  defp decode(json) do
    with {:ok, %{"v" => 1, "pairings" => list}} when is_list(list) <- JSON.decode(json),
         pairings = Enum.map(list, &pairing/1),
         false <- :error in pairings do
      {:ok, pairings}
    else
      _ -> {:error, :corrupt}
    end
  end

  defp pairing(%{} = m) do
    with true <- Record.self_node?(m["node"]),
         true <- Record.cookie?(m["cookie"]),
         true <- Enum.all?(["app_id", "app_name", "device_name"], &is_binary(m[&1])),
         true <- is_integer(m["paired_at"]),
         {:ok, fp} <- Wire.unb64(m["client_fp"], size: 32),
         {:ok, proto} <- proto(m["dist_proto"]) do
      %{
        node: m["node"],
        app_id: m["app_id"],
        app_name: m["app_name"],
        device_name: m["device_name"],
        client_fp: fp,
        dist_proto: proto,
        cookie: m["cookie"],
        paired_at: m["paired_at"]
      }
    else
      _ -> :error
    end
  end

  defp pairing(_), do: :error

  defp proto(nil), do: {:ok, nil}
  defp proto(value), do: Record.dist_proto(value)
end
