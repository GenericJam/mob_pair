defmodule MobPair.RecordTest do
  use ExUnit.Case, async: true

  alias MobPair.{Cert, Record}

  defp record(overrides \\ %{}) do
    me = Cert.self_signed("Humdinger")

    struct!(
      Record,
      Map.merge(
        %{
          service: "fmutate",
          inst: "a",
          name: "FMutate A",
          device: "Pixel 7",
          firmware: "X0X",
          node: "fmutate_a@192.168.1.23",
          host: "192.168.1.23",
          dist_port: 45_124,
          dist_proto: :inet_tls,
          fp: :crypto.strong_rand_bytes(32),
          cookie: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
          self_node: "humdinger_abc@127.0.0.1",
          cert: me.cert,
          key: me.key,
          paired_at: 1_790_000_000
        },
        overrides
      )
    )
  end

  test "a record survives the JSON round trip" do
    r = record()
    assert Record.from_json(Record.to_json(r)) == {:ok, r}
  end

  test "unreadable or tampered storage is an error, never a crash" do
    json = Record.to_json(record())

    for bad <- ["", "{", "[]", ~s({"v":2}), String.replace(json, "inet_tls", "inet_udp")] do
      assert {:error, _} = Record.from_json(bad)
    end

    assert Record.from_json(String.replace(json, "fmutate_a@", "Evil@")) ==
             {:error, {:invalid, :node}}
  end

  test "names, cookies and hosts from a grant are validated before they can become atoms" do
    assert Record.validate(record(%{node: "fmutate_a@192.168.1.23\n"})) ==
             {:error, {:invalid, :node}}

    assert Record.validate(record(%{self_node: "Humdinger@x"})) ==
             {:error, {:invalid, :self_node}}

    assert Record.validate(record(%{cookie: "short"})) == {:error, {:invalid, :cookie}}
    assert Record.validate(record(%{host: "fmutate.local"})) == {:error, {:invalid, :host}}
    assert Record.validate(record(%{dist_port: 0})) == {:error, {:invalid, :dist_port}}
  end

  test "plain distribution is only valid to a host on this phone" do
    assert Record.validate(record(%{dist_proto: :inet_tcp})) == {:error, {:invalid, :dist_proto}}

    assert {:ok, _} =
             Record.validate(
               record(%{dist_proto: :inet_tcp, host: "127.0.0.1", node: "fmutate_a@127.0.0.1"})
             )

    assert {:ok, _} = Record.validate(record(%{dist_proto: :inet_tls}))
  end

  test "the cookie and the TLS key never show in inspect (logs, crash reports)" do
    r = record()
    shown = inspect(r, limit: :infinity, printable_limit: :infinity)
    refute shown =~ r.cookie
    refute shown =~ inspect(r.key, limit: :infinity)
    assert shown =~ r.node
  end

  test "a record Humdinger stored before services existed loads as FMutate's" do
    r = record()
    legacy = r |> Record.to_json() |> JSON.decode!() |> Map.delete("service") |> JSON.encode!()
    assert Record.from_json(legacy) == {:ok, r}

    magpie = record(%{service: "magpie", node: "magpie_a@192.168.1.23"})
    assert Record.from_json(Record.to_json(magpie)) == {:ok, magpie}
    assert Record.validate(record(%{service: "Bad!"})) == {:error, {:invalid, :service}}
  end
end
