defmodule MobPair.PairingsTest.FlakyStore do
  @moduledoc false
  # FileStore whose save/delete fail on demand (a full disk, a read-only store).
  @behaviour MobPair.Pairings.Store

  alias MobPair.Pairings.FileStore

  def fail(path, ops), do: :persistent_term.put({__MODULE__, path}, ops)

  @impl true
  def load(opts), do: FileStore.load(opts)

  @impl true
  def save(pairings, opts),
    do: if(failing?(opts, :save), do: {:error, :enospc}, else: FileStore.save(pairings, opts))

  @impl true
  def delete(opts),
    do: if(failing?(opts, :delete), do: {:error, :erofs}, else: FileStore.delete(opts))

  defp failing?(opts, op), do: op in :persistent_term.get({__MODULE__, opts[:path]}, [])
end

defmodule MobPair.PairingsTest do
  # MobPair.Pairings is a named singleton (as on the host's node).
  use ExUnit.Case, async: false

  alias MobPair.Pairings
  alias MobPair.Pairings.FileStore
  alias MobPair.PairingsTest.FlakyStore

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

  test "a revoke sticks even with a net_setuptime net_kernel would ignore", %{store: store} do
    previous = Application.fetch_env(:kernel, :net_setuptime)
    Application.put_env(:kernel, :net_setuptime, :infinity)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:kernel, :net_setuptime, value)
        :error -> Application.delete_env(:kernel, :net_setuptime)
      end
    end)

    start_supervised!({Pairings, store: store})
    {:ok, _} = Pairings.add(request("humdinger_a@127.0.0.1"))
    assert :ok = Pairings.revoke("humdinger_a@127.0.0.1")
    stop_supervised!(Pairings)

    start_supervised!({Pairings, store: store})
    assert Pairings.list() == []
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

  describe "a store that fails" do
    setup %{path: path} do
      on_exit(fn -> :persistent_term.erase({FlakyStore, path}) end)
      %{store: {FlakyStore, path: path}}
    end

    test "a revoke isn't reported done, stays revoked, and the retried save drops it",
         %{path: path, store: store} do
      start_supervised!({Pairings, store: store})
      {:ok, a} = Pairings.add(request("humdinger_a@127.0.0.1"))
      {:ok, b} = Pairings.add(request("magpie_b@127.0.0.1"))

      FlakyStore.fail(path, [:save, :delete])
      assert Pairings.revoke(b.node) == {:error, {:store, :enospc}}
      refute Pairings.saved?()
      assert Pairings.get(b.node) == nil
      refute Pairings.pinned?(b.client_fp)
      # the disk still has b until a save works; then only a
      assert {:ok, [_, _]} = FileStore.load(path: path)

      FlakyStore.fail(path, [])
      assert eventually(fn -> FileStore.load(path: path) == {:ok, [a]} end)
      assert Pairings.saved?()
      assert Pairings.revoke(b.node) == :ok

      stop_supervised!(Pairings)
      start_supervised!({Pairings, store: {FileStore, path: path}})
      assert Pairings.list() == [a]
    end

    test "a revoke that can't be saved deletes the store, so a restart doesn't bring it back",
         %{path: path, store: store} do
      start_supervised!({Pairings, store: store})
      {:ok, _a} = Pairings.add(request("humdinger_a@127.0.0.1"))
      {:ok, b} = Pairings.add(request("magpie_b@127.0.0.1"))

      FlakyStore.fail(path, [:save])
      assert Pairings.revoke(b.node) == {:error, {:store, :enospc}}
      stop_supervised!(Pairings)

      start_supervised!({Pairings, store: {FileStore, path: path}})
      assert Pairings.get(b.node) == nil
      refute Pairings.pinned?(b.client_fp)
    end

    test "an add that can't be saved grants nothing; a pairing it replaced stays revoked",
         %{path: path, store: store} do
      start_supervised!({Pairings, store: store})
      :ok = Pairings.subscribe(self())
      {:ok, old} = Pairings.add(request("humdinger_a@127.0.0.1"))
      assert_receive {:mob_pair_pairings, :added, ^old}

      FlakyStore.fail(path, [:save, :delete])
      assert Pairings.add(request("magpie_b@127.0.0.1")) == {:error, {:store, :enospc}}
      assert Pairings.get("magpie_b@127.0.0.1") == nil

      replacement = request("humdinger_a@127.0.0.1", %{client_fp: :crypto.hash(:sha256, "new")})
      assert Pairings.add(replacement) == {:error, {:store, :enospc}}
      assert_receive {:mob_pair_pairings, :revoked, ^old}
      refute_receive {:mob_pair_pairings, :added, _}
      assert Pairings.list() == []
      refute Pairings.pinned?(old.client_fp)

      FlakyStore.fail(path, [])
      assert eventually(fn -> FileStore.load(path: path) == {:ok, []} end)
    end
  end

  test "add refuses what it would make atoms or cookies of, whoever calls it" do
    start_supervised!(Pairings)
    own = Atom.to_string(node())

    for bad <- [
          request("Not A Node"),
          request(String.duplicate("a", 300) <> "@127.0.0.1"),
          request(own),
          request("humdinger_a@127.0.0.1", %{cookie: "short"}),
          request("humdinger_a@127.0.0.1", %{client_fp: "fp"}),
          request("humdinger_a@127.0.0.1", %{dist_proto: :inet6_tcp})
        ] do
      assert Pairings.add(bad) == {:error, :invalid}, inspect(bad)
    end

    assert Pairings.list() == []
  end

  defp eventually(fun, tries \\ 50) do
    cond do
      fun.() ->
        true

      tries == 0 ->
        false

      true ->
        Process.sleep(100)
        eventually(fun, tries - 1)
    end
  end

  defp start_pairings_and_add(path, node) do
    start_supervised!({Pairings, store: {FileStore, path: path}})
    Pairings.add(request(node))
  end
end
