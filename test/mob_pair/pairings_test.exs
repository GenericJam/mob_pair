defmodule MobPair.PairingsTest do
  # MobPair.Pairings is a named singleton (as on the host's node).
  use ExUnit.Case, async: false

  alias MobPair.Pairings
  alias MobPair.Pairings.FileStore

  setup do
    path = Path.join(System.tmp_dir!(), "pairings_#{System.unique_integer([:positive])}.json")
    on_exit(fn -> File.rm(path) end)
    %{path: path, store: {FileStore, path: path}}
  end

  defp request(node, extra \\ %{}) do
    Map.merge(
      %{
        node: node,
        app_id: "com.genericjam.humdinger",
        app_name: "Humdinger",
        device_name: "Pixel 7",
        client_fp: :crypto.hash(:sha256, node),
        dist_proto: :inet_tls
      },
      extra
    )
  end

  describe "FileStore" do
    test "round trip, written private to its owner", %{path: path} do
      {:ok, a} = start_pairings_and_add(path, "humdinger_a@127.0.0.1")
      stop_supervised!(Pairings)

      assert FileStore.load(path: path) == {:ok, [a]}
      assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o600
    end

    test "a missing file is no pairings; an unreadable one is an error", %{path: path} do
      assert FileStore.load(path: path) == {:ok, []}

      for bad <- ["", "{", "[]", ~s({"v":1,"pairings":[{"node":"x"}]}), ~s({"v":2,"pairings":[]})] do
        File.write!(path, bad)
        assert FileStore.load(path: path) == {:error, :corrupt}, bad
      end
    end
  end

  test "stored pairings come back at start; add and revoke save the list", %{store: store} do
    start_supervised!({Pairings, store: store})
    {:ok, a} = Pairings.add(request("humdinger_a@127.0.0.1"))
    {:ok, _} = Pairings.add(request("magpie_b@127.0.0.1", %{dist_proto: :inet_tcp}))
    :ok = Pairings.revoke("magpie_b@127.0.0.1")
    stop_supervised!(Pairings)

    start_supervised!({Pairings, store: store})
    assert Pairings.list() == [a]
    assert Pairings.pinned?(a.client_fp)
  end

  test "an unreadable store starts empty instead of crashing", %{path: path, store: store} do
    File.write!(path, "{")
    start_supervised!({Pairings, store: store})
    assert Pairings.list() == []
  end

  test "node_for_fp names the node pinned to a client certificate" do
    start_supervised!(Pairings)
    {:ok, a} = Pairings.add(request("humdinger_a@127.0.0.1"))
    assert Pairings.node_for_fp(a.client_fp) == "humdinger_a@127.0.0.1"
    assert Pairings.node_for_fp(:crypto.hash(:sha256, "stranger")) == nil

    :ok = Pairings.revoke("humdinger_a@127.0.0.1")
    assert Pairings.node_for_fp(a.client_fp) == nil
  end

  test "subscribers hear about additions and revocations" do
    start_supervised!(Pairings)
    :ok = Pairings.subscribe(self())
    {:ok, a} = Pairings.add(request("humdinger_a@127.0.0.1"))
    assert_receive {:mob_pair_pairings, :added, ^a}
    :ok = Pairings.revoke("humdinger_a@127.0.0.1")
    assert_receive {:mob_pair_pairings, :revoked, ^a}
    :ok = Pairings.revoke("humdinger_a@127.0.0.1")
    refute_receive {:mob_pair_pairings, _, _}
  end

  test "one certificate, one node: a second node can't pin a pinned certificate" do
    start_supervised!(Pairings)
    {:ok, a} = Pairings.add(request("humdinger_a@127.0.0.1"))

    assert Pairings.add(request("magpie_b@127.0.0.1", %{client_fp: a.client_fp})) ==
             {:error, :fingerprint_in_use}

    assert Pairings.list() == [a]
  end

  test "a pairing replaced under the same node name is revoked first" do
    start_supervised!(Pairings)
    :ok = Pairings.subscribe(self())
    {:ok, old} = Pairings.add(request("humdinger_a@127.0.0.1"))
    assert_receive {:mob_pair_pairings, :added, ^old}

    {:ok, new} =
      Pairings.add(request("humdinger_a@127.0.0.1", %{client_fp: :crypto.hash(:sha256, "new")}))

    assert_receive {:mob_pair_pairings, :revoked, ^old}
    assert_receive {:mob_pair_pairings, :added, ^new}
    assert Pairings.node_for_fp(old.client_fp) == nil
    assert Pairings.list() == [new]
  end

  defp start_pairings_and_add(path, node) do
    start_supervised!({Pairings, store: {FileStore, path: path}})
    Pairings.add(request(node))
  end
end
