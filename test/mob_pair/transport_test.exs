defmodule MobPair.TransportTest do
  # Touches this VM's distribution state.
  use ExUnit.Case, async: false

  alias MobPair.{Cert, Record, Transport}

  test "plain distribution to a host on the network is refused before anything starts" do
    me = Cert.self_signed("Humdinger")

    record = %Record{
      service: "fmutate",
      inst: "a",
      node: "fmutate_a@192.168.1.23",
      host: "192.168.1.23",
      dist_port: 45_124,
      dist_proto: :inet_tcp,
      fp: :crypto.hash(:sha256, "fmutate"),
      cookie: String.duplicate("c", 43),
      self_node: "humdinger_t@127.0.0.1",
      cert: me.cert,
      key: me.key
    }

    assert Transport.connect(record, self()) == {:error, :plain_distribution_off_loopback}
    refute Node.alive?()
  end

  test "a record or node name that isn't well formed is refused before anything becomes an atom" do
    me = Cert.self_signed("Humdinger")
    fresh = "zz#{System.unique_integer([:positive])}"

    record = %Record{
      service: "fmutate",
      inst: "a",
      node: "fmutate_a@127.0.0.1",
      host: "127.0.0.1",
      dist_port: 45_124,
      dist_proto: :inet_tcp,
      fp: :crypto.hash(:sha256, "fmutate"),
      cookie: "#{fresh} not a cookie",
      self_node: "humdinger_t@127.0.0.1",
      cert: me.cert,
      key: me.key
    }

    assert Transport.connect(record, self()) == {:error, {:invalid, :cookie}}

    assert Transport.connect(
             %{record | cookie: String.duplicate("c", 43), node: "#{fresh} x"},
             self()
           ) ==
             {:error, {:invalid, :node}}

    assert Transport.start_node("#{fresh} y@127.0.0.1") == {:error, {:invalid, :self_node}}
    refute Node.alive?()

    for name <- ["#{fresh} not a cookie", "#{fresh} x", "#{fresh} y@127.0.0.1"],
        do: assert_raise(ArgumentError, fn -> String.to_existing_atom(name) end)
  end
end
