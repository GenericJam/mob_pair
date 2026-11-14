defmodule MobPair.DistTest do
  @moduledoc false
  # End to end against a real second BEAM: the host (MobPair.Pairings,
  # MobPair.Host and a registered echo process) runs in a :peer node with no
  # epmd (MobPair.FixedEpmd, a fixed port), and this test VM is the joiner:
  # it pairs with MobPair.Client, starts its own hidden node without a
  # listener, and connects with the per-app cookie. These tests start and
  # stop distribution in this VM, so they run alone.
  use ExUnit.Case, async: false

  alias MobPair.{Cert, Client, Code, Epmd, Host, Link, Pairings, Record, Transport, Tunnel}
  alias MobPair.Pairings.FileStore

  @moduletag :capture_log

  # The distribution flags OTP 26+ requires of a peer (dist.hrl: the OTP 25 and 26 mandatory
  # sets, which include DFLAG_HANDSHAKE_23); no DFLAG_PUBLISHED: a hidden node.
  @dist_flags Enum.reduce(
                [0x04, 0x10, 0x80, 0x100, 0x200, 0x400, 0x800, 0x10000, 0x20000, 0x40000],
                0x1000000 + 0x2000000 + 0x04 * 0x100000000,
                &(&1 + &2)
              )

  @host_module """
  defmodule MobPairTestHost do
    def allow(_request), do: :allow

    def start(pairings, host, front) do
      children =
        [
          {MobPair.Pairings, pairings},
          {MobPair.Host, host},
          %{id: :echo, start: {__MODULE__, :start_echo, []}}
        ] ++ if(front, do: [{MobPair.Front, front}], else: [])

      {:ok, sup} = Supervisor.start_link(children, strategy: :one_for_one)
      Process.unlink(sup)
      {:ok, sup}
    end

    def start_echo do
      pid = spawn_link(&echo/0)
      Process.register(pid, :mob_pair_echo)
      {:ok, pid}
    end

    defp echo do
      receive do
        {from, message} -> send(from, {:echo, message})
      end

      echo()
    end
  end
  """

  setup do
    :ok = Transport.setup()

    on_exit(fn ->
      if Node.alive?(), do: :net_kernel.stop()
      :application.unset_env(:kernel, :dist_auto_connect)
      :persistent_term.erase({Epmd, :routes})
    end)

    :ok
  end

  # :inet_tcp (plain, loopback), :inet_tls (stock inet_tls_dist) or :front: a plain loopback node
  # whose TLS distribution is MobPair.Front, as FMutate runs it (the Host grants TLS to the front
  # even to loopback joiners here, so the test VM exercises the front).
  defp start_host(proto, pairings \\ [], front_ip \\ {127, 0, 0, 1}) do
    port = free_port()
    front_port = if proto == :front, do: free_port()
    name = "fmutate_t#{System.unique_integer([:positive])}"
    cert = Cert.self_signed("FMutate A")
    optfile = Path.join(System.tmp_dir!(), "#{name}_ssl_dist.conf")

    if proto == :inet_tls do
      :ok = Pairings.write_ssl_dist_optfile(optfile, cert)
      on_exit(fn -> File.rm(optfile) end)
    end

    boot_proto = if proto == :front, do: :inet_tcp, else: proto
    boot = MobPair.boot_args(dist_port: port, dist_proto: boot_proto, ssl_dist_optfile: optfile)

    args =
      Enum.map(boot, &String.to_charlist/1) ++ Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

    {:ok, peer, node} =
      :peer.start(%{
        name: String.to_atom(name),
        host: ~c"127.0.0.1",
        longnames: true,
        connection: :standard_io,
        args: args
      })

    on_exit(fn -> if Process.alive?(peer), do: :peer.stop(peer) end)

    {:ok, _} = :peer.call(peer, Application, :ensure_all_started, [:elixir])
    {:ok, _} = :peer.call(peer, Application, :ensure_all_started, [:ssl])
    :peer.call(peer, Elixir.Code, :compile_string, [@host_module])

    host =
      [
        service: "fmutate",
        name: "FMutate A",
        server_name: Host,
        cert: cert,
        ip: {127, 0, 0, 1},
        host: "127.0.0.1",
        node: Atom.to_string(node),
        device: "Studio Mac",
        firmware: "X0X",
        approve: Function.capture(MobPairTestHost, :allow, 1)
      ] ++
        if proto == :front,
          do: [
            dist_port: front_port,
            dist_proto: :inet_tls,
            loopback_dist: %{port: front_port, proto: :inet_tls}
          ],
          else: [dist_port: port, dist_proto: proto]

    front =
      if proto == :front,
        do: [cert: cert, ip: front_ip, port: front_port, target: {{127, 0, 0, 1}, port}]

    {:ok, _} = :peer.call(peer, MobPairTestHost, :start, [pairings, host, front])
    %{peer: peer, node: node, port: port, front_port: front_port, cert: cert}
  end

  defp identity do
    %{
      app_id: "com.genericjam.humdinger",
      app_name: "Humdinger",
      device_name: "Test phone",
      node: Transport.random_node_name("humdinger"),
      cert: Cert.self_signed("Humdinger")
    }
  end

  defp target(host),
    do: %{
      service: "fmutate",
      host: "127.0.0.1",
      port: :peer.call(host.peer, Host, :port, [Host]),
      inst: "a",
      fp: host.cert.fp
    }

  defp echo(conn, message) do
    send({:mob_pair_echo, conn.node}, {self(), message})
    assert_receive {:echo, ^message}, 5_000
  end

  defp revoke_cuts(host, conn, record) do
    me = node()
    Node.monitor(conn.node, true)
    :ok = :peer.call(host.peer, Pairings, :revoke, [me])
    assert_receive {:nodedown, node} when node == conn.node, 5_000
    Transport.disconnect(conn)
    assert {:error, _} = Transport.connect(record, self())
  end

  test "same phone: pair from the link, connect over loopback with the per-app cookie, revoke" do
    host = start_host(:inet_tcp)
    {:ok, link} = Link.parse(:peer.call(host.peer, Host, :link, [Host]))

    assert {:ok, %Record{dist_proto: :inet_tcp, host: "127.0.0.1"} = record} =
             Client.pair(target(host), {:token, link.token}, identity())

    assert {:ok, conn} = Transport.connect(record, self())
    assert Atom.to_string(node()) == record.self_node
    # A hidden connection on both sides.
    assert host.node in Node.list(:hidden)
    refute host.node in Node.list()
    assert node() in :peer.call(host.peer, :erlang, :nodes, [:hidden])
    assert_no_epmd([node(), host.node])
    echo(conn, :hello)

    revoke_cuts(host, conn, record)
  end

  test "another phone: pair by code, TLS distribution through the tunnel, revoke" do
    host = start_host(:inet_tls)
    {:ok, code} = Code.normalize(:peer.call(host.peer, Host, :code, [Host]))

    assert {:ok, %Record{dist_proto: :inet_tls} = record} =
             Client.pair(%{target(host) | fp: nil}, {:code, code}, identity())

    assert [%{dist_proto: :inet_tls}] = :peer.call(host.peer, Pairings, :list, [])
    assert {:ok, %{tunnel: tunnel} = conn} = Transport.connect(record, self())
    assert is_pid(tunnel)
    assert_no_epmd([node(), host.node])
    echo(conn, :crypto.strong_rand_bytes(100_000))

    # TLS distribution only admits the client certificate the host pinned
    # (TLS 1.3 checks it after the client's handshake, so the host aborts the
    # session), and the joiner's tunnel only talks to the host's certificate.
    intruder = Cert.self_signed("Intruder")

    {:ok, socket} =
      :ssl.connect(~c"127.0.0.1", host.port, intruder_options(record, intruder), 5_000)

    assert {:error, _} = :ssl.recv(socket, 0, 5_000)
    assert {:error, {:tls, _}} = Tunnel.open(%{record | fp: intruder.fp}, self())

    revoke_cuts(host, conn, record)
  end

  test "a host with plain loopback distribution serves TLS through the front, then revokes" do
    host = start_host(:front)
    {:ok, link} = Link.parse(:peer.call(host.peer, Host, :link, [Host]))

    assert {:ok, %Record{dist_proto: :inet_tls, dist_port: front_port} = record} =
             Client.pair(target(host), {:token, link.token}, identity())

    assert front_port == host.front_port
    assert {:ok, %{tunnel: tunnel} = conn} = Transport.connect(record, self())
    assert is_pid(tunnel)
    # the host sees an ordinary (hidden) connection under the paired name
    assert node() in :peer.call(host.peer, :erlang, :nodes, [:hidden])
    echo(conn, :crypto.strong_rand_bytes(100_000))

    revoke_cuts(host, conn, record)
  end

  test "the front binds a pinned certificate to its paired node name" do
    host = start_host(:front)
    {:ok, first} = Link.parse(:peer.call(host.peer, Host, :link, [Host]))
    {:ok, a} = Client.pair(target(host), {:token, first.token}, identity())
    :ok = :peer.call(host.peer, Host, :renew, [Host])
    {:ok, second} = Link.parse(:peer.call(host.peer, Host, :link, [Host]))
    {:ok, b} = Client.pair(target(host), {:token, second.token}, identity())

    # a's name and cookie with b's (pinned) certificate: the front closes it at the first message
    borrowed = %{a | cert: b.cert, key: b.key}
    assert {:error, :rejected} = Transport.connect(borrowed, self())
    refute node() in :peer.call(host.peer, :erlang, :nodes, [:hidden])

    # and a certificate no pairing pinned doesn't get through TLS
    intruder = Cert.self_signed("Intruder")

    {:ok, socket} =
      :ssl.connect(~c"127.0.0.1", host.front_port, intruder_options(a, intruder), 5_000)

    assert {:error, _} = :ssl.recv(socket, 0, 5_000)

    # the genuine pairing still connects
    :net_kernel.stop()
    assert {:ok, conn} = Transport.connect(a, self())
    echo(conn, :mine)
  end

  test "pairings restored from the store get their cookies back" do
    path = Path.join(System.tmp_dir!(), "pairings_#{System.unique_integer([:positive])}.json")
    on_exit(fn -> File.rm(path) end)
    me = Cert.self_signed("Humdinger")
    self_node = Transport.random_node_name("humdinger")
    cookie = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    :ok =
      FileStore.save(
        [
          %{
            node: self_node,
            app_id: "com.genericjam.humdinger",
            app_name: "Humdinger",
            device_name: "Test phone",
            client_fp: Cert.fingerprint(me.cert),
            dist_proto: :inet_tcp,
            cookie: cookie,
            paired_at: 1_790_000_000
          }
        ],
        path: path
      )

    host = start_host(:inet_tcp, store: {FileStore, path: path})

    record = %Record{
      service: "fmutate",
      inst: "a",
      node: Atom.to_string(host.node),
      host: "127.0.0.1",
      dist_port: host.port,
      dist_proto: :inet_tcp,
      fp: host.cert.fp,
      cookie: cookie,
      self_node: self_node,
      cert: me.cert,
      key: me.key
    }

    assert {:ok, conn} = Transport.connect(record, self())
    echo(conn, :restored)
  end

  defp intruder_options(record, intruder) do
    [
      verify: :verify_peer,
      cacerts: [],
      verify_fun: Cert.verify_fun(record.fp),
      certs_keys: [Cert.ssl_cert_key(intruder.cert, intruder.key)],
      versions: [:"tlsv1.3"],
      active: false
    ]
  end

  test "the host refuses distribution under any unpaired name, even with its default cookie" do
    host = start_host(:inet_tcp)
    default_cookie = :peer.call(host.peer, :erlang, :get_cookie, [])

    {:ok, intruder, _} =
      :peer.start(%{
        name: :"intruder_#{System.unique_integer([:positive])}",
        host: ~c"127.0.0.1",
        longnames: true,
        connection: :standard_io,
        args:
          [
            ~c"-setcookie",
            Atom.to_charlist(default_cookie),
            ~c"-epmd_module",
            ~c"Elixir.MobPair.Epmd"
          ] ++
            Enum.flat_map(:code.get_path(), &[~c"-pa", &1])
      })

    on_exit(fn -> if Process.alive?(intruder), do: :peer.stop(intruder) end)
    :ok = :peer.call(intruder, Epmd, :put_route, [host.node, {{127, 0, 0, 1}, host.port}])

    refute :peer.call(intruder, :net_kernel, :connect_node, [host.node])
    # The host's plain listener (and so every socket on its port) is on loopback only.
    on_port = tcp_sockets(host.peer) |> Enum.filter(&match?({_, p} when p == host.port, &1))
    assert on_port != []
    assert Enum.all?(on_port, &match?({{127, 0, 0, 1}, _}, &1))
  end

  # Any app on the phone can reach the loopback listener and declare a name: OTP's handshake makes
  # an atom of it unless the allow list (never empty: :allow_list :auto) refuses it first.
  test "names the host never paired don't become atoms there, however many are tried" do
    host = start_host(:inet_tcp)
    atoms = fn -> :peer.call(host.peer, :erlang, :system_info, [:atom_count]) end
    prefix = "intruder#{System.unique_integer([:positive])}x"

    try_name = fn i ->
      name = "#{prefix}#{i}@127.0.0.1"

      {:ok, socket} =
        :gen_tcp.connect(~c"127.0.0.1", host.port, [:binary, active: false, packet: 2])

      :ok =
        :gen_tcp.send(socket, <<?N, @dist_flags::64, 1::32, byte_size(name)::16, name::binary>>)

      assert {:ok, "snot_allowed"} = :gen_tcp.recv(socket, 0, 5_000)
      :gen_tcp.close(socket)
    end

    # the first refusals load the code that reports them
    Enum.each(1..20, try_name)
    before = atoms.()
    Enum.each(21..520, try_name)

    assert atoms.() - before < 20
    refute Enum.any?(1..520, &atom_on?(host.peer, "#{prefix}#{&1}@127.0.0.1"))
  end

  defp atom_on?(peer, name) do
    _ = :peer.call(peer, :erlang, :binary_to_existing_atom, [name])
    true
  rescue
    _ -> false
  end

  describe "revocation and admission" do
    test "revoking aborts a handshake that already read the old cookie" do
      host = start_host(:inet_tcp)
      name = Transport.random_node_name("humdinger")

      {:ok, pairing} =
        :peer.call(host.peer, Pairings, :add, [
          %{
            node: name,
            app_id: "com.genericjam.humdinger",
            app_name: "Humdinger",
            device_name: "Test phone",
            client_fp: :crypto.strong_rand_bytes(32),
            dist_proto: :inet_tcp
          }
        ])

      # Our side of the handshake by hand, up to the host's challenge: the
      # host's handshake has read the pairing's cookie by then.
      {:ok, socket} =
        :gen_tcp.connect(~c"127.0.0.1", host.port, [:binary, active: false, packet: 2])

      :ok =
        :gen_tcp.send(socket, <<?N, @dist_flags::64, 1::32, byte_size(name)::16, name::binary>>)

      assert {:ok, "sok"} = :gen_tcp.recv(socket, 0, 5_000)
      assert {:ok, <<?N, _::64, challenge::32, _::binary>>} = :gen_tcp.recv(socket, 0, 5_000)

      :ok = :peer.call(host.peer, Pairings, :revoke, [name])

      digest = :erlang.md5([pairing.cookie, Integer.to_string(challenge)])
      :ok = :gen_tcp.send(socket, <<?r, 42::32, digest::binary>>)
      assert {:error, :closed} = :gen_tcp.recv(socket, 0, 5_000)
      refute String.to_atom(name) in :peer.call(host.peer, :erlang, :nodes, [:hidden])
    end

    test "revoking aborts a handshake parked behind the node's live connection" do
      host = start_host(:inet_tcp)
      {:ok, link} = Link.parse(:peer.call(host.peer, Host, :link, [Host]))
      {:ok, record} = Client.pair(target(host), {:token, link.token}, identity())
      {:ok, _conn} = Transport.connect(record, self())
      name = record.self_node

      # a second handshake under the connected name waits (up_pending) for the first to go
      {:ok, socket} =
        :gen_tcp.connect(~c"127.0.0.1", host.port, [:binary, active: false, packet: 2])

      :ok =
        :gen_tcp.send(socket, <<?N, @dist_flags::64, 1::32, byte_size(name)::16, name::binary>>)

      assert {:ok, "salive"} = :gen_tcp.recv(socket, 0, 5_000)
      :ok = :gen_tcp.send(socket, "strue")
      assert {:ok, <<?N, _::64, challenge::32, _::binary>>} = :gen_tcp.recv(socket, 0, 5_000)

      :ok = :peer.call(host.peer, Pairings, :revoke, [name])

      digest = :erlang.md5([record.cookie, Integer.to_string(challenge)])
      :ok = :gen_tcp.send(socket, <<?r, 42::32, digest::binary>>)
      assert {:error, :closed} = :gen_tcp.recv(socket, 0, 5_000)
    end

    test "a revoked name may come back another way once the revoke's window is over" do
      host = start_host(:inet_tcp)
      # the window is twice net_setuptime: 2 s here
      :ok = :peer.call(host.peer, :application, :set_env, [:kernel, :net_setuptime, 1])
      {:ok, link} = Link.parse(:peer.call(host.peer, Host, :link, [Host]))
      {:ok, record} = Client.pair(target(host), {:token, link.token}, identity())
      {:ok, conn} = Transport.connect(record, self())
      Node.monitor(conn.node, true)
      :ok = :peer.call(host.peer, Pairings, :revoke, [record.self_node])
      assert_receive {:nodedown, _}, 5_000
      Transport.disconnect(conn)

      # the host lets the name in with another cookie (FMutate: its same-key Allow)
      other = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
      true = :peer.call(host.peer, :erlang, :set_cookie, [node(), String.to_atom(other)])
      Process.sleep(2_500)

      assert {:ok, conn} = Transport.connect(%{record | cookie: other}, self())
      Process.sleep(500)
      assert node() in :peer.call(host.peer, :erlang, :nodes, [:hidden])
      echo(conn, :back_again)
    end

    test "replacing a pairing drops the old app's connection" do
      host = start_host(:inet_tcp)
      {:ok, link} = Link.parse(:peer.call(host.peer, Host, :link, [Host]))
      {:ok, record} = Client.pair(target(host), {:token, link.token}, identity())
      {:ok, conn} = Transport.connect(record, self())
      Node.monitor(conn.node, true)

      {:ok, _} =
        :peer.call(host.peer, Pairings, :add, [
          %{
            node: record.self_node,
            app_id: "com.example.other",
            app_name: "Other",
            device_name: "Other phone",
            client_fp: :crypto.strong_rand_bytes(32),
            dist_proto: :inet_tcp
          }
        ])

      assert_receive {:nodedown, node} when node == conn.node, 5_000
    end

    test "a host whose distribution starts later gets its pairings at distribution_started/0" do
      path = Path.join(System.tmp_dir!(), "pairings_#{System.unique_integer([:positive])}.json")
      on_exit(fn -> File.rm(path) end)
      me = Cert.self_signed("Humdinger")
      self_node = Transport.random_node_name("humdinger")
      cookie = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

      :ok =
        FileStore.save(
          [
            %{
              node: self_node,
              app_id: "com.genericjam.humdinger",
              app_name: "Humdinger",
              device_name: "Test phone",
              client_fp: Cert.fingerprint(me.cert),
              dist_proto: :inet_tcp,
              cookie: cookie,
              paired_at: 1_790_000_000
            }
          ],
          path: path
        )

      port = free_port()
      boot = MobPair.boot_args(dist_port: port, dist_proto: :inet_tcp)

      args =
        Enum.map(boot, &String.to_charlist/1) ++ Enum.flat_map(:code.get_path(), &[~c"-pa", &1])

      {:ok, peer, :nonode@nohost} = :peer.start(%{connection: :standard_io, args: args})
      on_exit(fn -> if Process.alive?(peer), do: :peer.stop(peer) end)
      {:ok, _} = :peer.call(peer, Application, :ensure_all_started, [:elixir])

      {:ok, _} =
        :peer.call(peer, GenServer, :start, [
          Pairings,
          [store: {FileStore, path: path}],
          [name: Pairings]
        ])

      refute :peer.call(peer, Node, :alive?, [])
      name = :"fmutate_late#{System.unique_integer([:positive])}@127.0.0.1"
      {:ok, _} = :peer.call(peer, :net_kernel, :start, [name, %{name_domain: :longnames}])
      :ok = :peer.call(peer, Pairings, :distribution_started, [])

      record = %Record{
        service: "fmutate",
        inst: "a",
        node: Atom.to_string(name),
        host: "127.0.0.1",
        dist_port: port,
        dist_proto: :inet_tcp,
        fp: :crypto.strong_rand_bytes(32),
        cookie: cookie,
        self_node: self_node,
        cert: me.cert,
        key: me.key
      }

      assert {:ok, _conn} = Transport.connect(record, self())
    end

    test "idle connections from one address can't hold the front's slots" do
      lan = lan_ip()
      host = start_host(:front, [], {0, 0, 0, 0})
      {:ok, link} = Link.parse(:peer.call(host.peer, Host, :link, [Host]))
      {:ok, record} = Client.pair(target(host), {:token, link.token}, identity())

      idle =
        for _ <- 1..8,
            {:ok, socket} <- [:gen_tcp.connect(~c"127.0.0.1", host.front_port, active: false)],
            do: socket

      on_exit(fn -> Enum.each(idle, &:gen_tcp.close/1) end)
      assert {:ok, conn} = Transport.connect(%{record | host: lan}, self())
      echo(conn, :through_the_crowd)
    end
  end

  defp lan_ip do
    {:ok, interfaces} = :inet.getifaddrs()

    ip =
      Enum.find_value(interfaces, fn {_name, opts} ->
        Enum.find(Keyword.get_values(opts, :addr), &match?({a, _, _, _} when a != 127, &1))
      end) || flunk("needs a non-loopback IPv4 address")

    ip |> :inet.ntoa() |> List.to_string()
  end

  defp tcp_sockets(peer) do
    for port <- :peer.call(peer, :erlang, :ports, []),
        :peer.call(peer, :erlang, :port_info, [port, :name]) == {:name, ~c"tcp_inet"},
        {:ok, address} <- [:peer.call(peer, :inet, :sockname, [port])],
        do: address
  end

  defp assert_no_epmd(nodes) do
    case :erl_epmd.names(~c"127.0.0.1") do
      {:ok, names} ->
        registered = for {name, _port} <- names, do: List.to_string(name)
        for node <- nodes, do: refute(hd(String.split(Atom.to_string(node), "@")) in registered)

      {:error, _no_epmd} ->
        :ok
    end
  end

  defp free_port do
    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end
end
