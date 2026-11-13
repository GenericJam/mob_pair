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
end
