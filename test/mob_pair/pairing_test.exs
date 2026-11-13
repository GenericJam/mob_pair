defmodule MobPair.PairingTest do
  # MobPair.Pairings is a named singleton (as on the host's node).
  use ExUnit.Case, async: false

  alias MobPair.{Cert, Client, Discovery, Host, Join, Link, Pairings, Responder}

  @self_node "humdinger_test@127.0.0.1"

  setup do
    start_supervised!(Pairings)
    :ok
  end

  defp start_server(opts) do
    defaults = [
      service: "fmutate",
      name: "FMutate A",
      cert: Cert.self_signed("FMutate A"),
      ip: {127, 0, 0, 1},
      host: "127.0.0.1",
      node: "fmutate_a@127.0.0.1",
      dist_port: 45_124,
      device: "Studio Mac",
      firmware: "X0X",
      approve: fn _request -> :allow end
    ]

    opts = Keyword.merge(defaults, opts)
    server = start_supervised!({Host, opts}, id: make_ref())
    {server, opts[:cert]}
  end

  defp start_pairing(opts \\ []) do
    test = self()

    defaults = [
      name: nil,
      service: "fmutate",
      app_id: "com.genericjam.humdinger",
      app_name: "Humdinger",
      install: fn record -> send(test, {:installed, record}) && :ok end,
      self_node: fn -> @self_node end,
      device_name: "Test phone",
      discovery: fn _ -> {:ok, []} end
    ]

    start_supervised!({Join, Keyword.merge(defaults, opts)}, id: make_ref())
  end

  defp target(server, fp \\ nil),
    do: %{service: "fmutate", host: "127.0.0.1", port: Host.port(server), inst: "a", fp: fp}

  defp identity do
    %{
      app_id: "com.genericjam.humdinger",
      app_name: "Humdinger",
      device_name: "Test phone",
      node: @self_node,
      cert: Cert.self_signed("Humdinger")
    }
  end

  defp code(server) do
    {:ok, code} = MobPair.Code.normalize(Host.code(server))
    code
  end

  test "pairs from the QR link: pinned TLS, token, Allow, a record FMutate recognises" do
    {server, fmutate} = start_server(dist_proto: :inet_tcp)
    pairing = start_pairing()
    {:ok, offer} = Link.parse(Host.link(server))

    :ok = Join.pair(self(), offer, pairing)

    # A link only names the service: the candidate is "<Service> <INST>".
    assert_receive {:mob_pair, :matched, %{name: "Fmutate A", fp: fp}}
    assert fp == fmutate.fp
    assert_receive {:mob_pair, :waiting}
    assert_receive {:installed, record}

    assert_receive {:mob_pair, :paired,
                    %{name: "FMutate A", device: "Studio Mac", firmware: "X0X", same_phone: true}}

    assert record.fp == fmutate.fp
    assert record.node == "fmutate_a@127.0.0.1"
    assert {record.host, record.dist_port, record.dist_proto} == {"127.0.0.1", 45_124, :inet_tcp}
    assert record.self_node == @self_node

    assert [paired] = Pairings.list()
    assert paired.node == @self_node
    assert paired.cookie == record.cookie
    assert paired.client_fp == Cert.fingerprint(record.cert)
    assert paired.device_name == "Test phone"
  end

  test "pairs by typed code with an FMutate found over mDNS" do
    {server, fmutate} = start_server(advertise: [bind: {{127, 0, 0, 1}, 0}])
    mdns = {{127, 0, 0, 1}, Responder.port(Host.responder(server))}

    pairing =
      start_pairing(
        discovery: &Discovery.browse/1,
        discovery_opts: [targets: [mdns], timeout: 300]
      )

    :ok = Join.discover(self(), pairing)
    assert_receive {:mob_pair, :found, [candidate]}, 2_000

    assert %{
             name: "FMutate A",
             inst: "a",
             firmware: "X0X",
             device: "Studio Mac",
             node: "fmutate_a@127.0.0.1"
           } = candidate

    assert candidate.fp == fmutate.fp
    assert candidate.port == Host.port(server)

    :ok = Join.pair(self(), %{code: String.downcase(Host.code(server))}, pairing)

    assert_receive {:mob_pair, :matched, ^candidate}, 2_000
    assert_receive {:mob_pair, :waiting}
    assert_receive {:installed, %{fp: fp}}
    assert fp == fmutate.fp
    assert_receive {:mob_pair, :paired, %{name: "FMutate A"}}
  end

  test "a typed code tries each FMutate nearby until one knows it" do
    {other, _} = start_server([])
    {server, fmutate} = start_server([])
    candidates = for s <- [other, server], do: candidate(s)
    pairing = start_pairing(discovery: fn _ -> {:ok, candidates} end)

    :ok = Join.pair(self(), %{code: Host.code(server)}, pairing)

    assert_receive {:installed, record}, 5_000
    assert record.fp == fmutate.fp
    assert_receive {:mob_pair, :paired, _}
    # The other FMutate counted a wrong attempt.
    assert {:error, {:wrong_code, 3}} =
             Client.pair(target(other), {:code, "00000000"}, identity())
  end

  test "five wrong codes invalidate the code and the link; New code starts over" do
    {server, _} = start_server([])
    {:ok, link} = Link.parse(Host.link(server))

    results = for _ <- 1..5, do: Client.pair(target(server), {:code, "00000000"}, identity())

    assert results == [
             {:error, {:wrong_code, 4}},
             {:error, {:wrong_code, 3}},
             {:error, {:wrong_code, 2}},
             {:error, {:wrong_code, 1}},
             {:error, :too_many_attempts}
           ]

    assert Client.pair(target(server), {:code, code(server)}, identity()) ==
             {:error, :too_many_attempts}

    assert Client.pair(target(server, link.fp), {:token, link.token}, identity()) ==
             {:error, :too_many_attempts}

    :ok = Host.renew(server)
    assert {:ok, _} = Client.pair(target(server), {:code, code(server)}, identity())
  end

  test "a wrong token counts as a failed attempt" do
    {server, fmutate} = start_server([])

    assert Client.pair(target(server, fmutate.fp), {:token, <<0::128>>}, identity()) ==
             {:error, :invalid_token}

    assert {:error, {:wrong_code, 3}} =
             Client.pair(target(server), {:code, "00000000"}, identity())
  end

  test "the secret is single use and expires" do
    {server, _} = start_server(ttl: 1_000)
    {:ok, link} = Link.parse(Host.link(server))
    code = code(server)

    assert {:ok, _} = Client.pair(target(server, link.fp), {:token, link.token}, identity())

    assert Client.pair(target(server, link.fp), {:token, link.token}, identity()) ==
             {:error, :expired}

    assert Client.pair(target(server), {:code, code}, identity()) == {:error, :expired}

    :ok = Host.renew(server)
    {:ok, link} = Link.parse(Host.link(server))
    Process.sleep(1_050)

    assert Client.pair(target(server, link.fp), {:token, link.token}, identity()) ==
             {:error, :expired}
  end

  test "a link whose fingerprint isn't FMutate's certificate is refused before anything is sent" do
    {server, _} = start_server([])
    {:ok, link} = Link.parse(Host.link(server))
    impostor = Cert.self_signed("Impostor").fp

    assert Client.pair(target(server, impostor), {:token, link.token}, identity()) ==
             {:error, :fingerprint_mismatch}

    # Nothing reached FMutate: the token is still good.
    assert {:ok, _} = Client.pair(target(server, link.fp), {:token, link.token}, identity())
  end

  test "the player's Deny and Allow" do
    {server, _} = start_server(approve: {:ask, self()})
    pairing = start_pairing()
    {:ok, offer} = Link.parse(Host.link(server))

    :ok = Join.pair(self(), offer, pairing)
    assert_receive {:mob_pair_request, ^server, ref, request}

    assert %{
             app_id: "com.genericjam.humdinger",
             app_name: "Humdinger",
             device_name: "Test phone",
             node: @self_node
           } = request

    assert request.remote_ip == {127, 0, 0, 1}
    :ok = Host.decide(server, ref, :deny)
    assert_receive {:mob_pair, :failed, :denied}
    refute_received {:installed, _}
    assert Pairings.list() == []

    :ok = Host.renew(server)
    {:ok, offer} = Link.parse(Host.link(server))
    :ok = Join.pair(self(), offer, pairing)
    assert_receive {:mob_pair_request, ^server, ref, _}
    :ok = Host.decide(server, ref, :allow)
    assert_receive {:mob_pair, :paired, _}
    assert [%{node: @self_node}] = Pairings.list()
  end

  test "cancelling withdraws the request on FMutate" do
    {server, _} = start_server(approve: {:ask, self()})
    pairing = start_pairing()
    {:ok, offer} = Link.parse(Host.link(server))

    :ok = Join.pair(self(), offer, pairing)
    assert_receive {:mob_pair, :waiting}
    assert_receive {:mob_pair_request, ^server, ref, _}

    :ok = Join.cancel(pairing)
    assert_receive {:mob_pair_withdrawn, ^server, ^ref}, 2_000
    refute_received {:mob_pair, :failed, _}
  end

  test "a typed code with no FMutate showing its code nearby" do
    pairing = start_pairing(discovery: fn _ -> {:ok, [%{candidate(nil) | port: nil}]} end)
    :ok = Join.pair(self(), %{code: "KQ7M-X2PD"}, pairing)
    assert_receive {:mob_pair, :failed, :not_found}
    assert Join.pair(self(), %{code: "KQ7M"}, pairing) == {:error, :invalid_code}
  end

  describe "carriers" do
    test "a sibling on another phone is always granted TLS distribution" do
      lan = lan_ip()
      {server, fmutate} = start_server(ip: {0, 0, 0, 0}, host: lan, dist_proto: :inet_tls)
      {:ok, link} = Link.parse(Host.link(server))

      assert {:ok, record} =
               Client.pair(
                 %{target(server, fmutate.fp) | host: lan},
                 {:token, link.token},
                 identity()
               )

      assert {record.dist_proto, record.host} == {:inet_tls, lan}
    end

    test "an FMutate with plain distribution pairs only apps on its own phone" do
      lan = lan_ip()
      {server, fmutate} = start_server(ip: {0, 0, 0, 0}, host: lan, dist_proto: :inet_tcp)
      {:ok, link} = Link.parse(Host.link(server))
      remote = %{target(server, fmutate.fp) | host: lan}

      assert Client.pair(remote, {:token, link.token}, identity()) == {:error, :loopback_only}
      # Turned away before authenticating: the token is still good on loopback.
      assert {:ok, record} =
               Client.pair(target(server, fmutate.fp), {:token, link.token}, identity())

      assert {record.dist_proto, record.host} == {:inet_tcp, "127.0.0.1"}
    end

    test "siblings on the same phone get the loopback carrier, recorded with the pairing" do
      lan = lan_ip()

      {server, fmutate} =
        start_server(
          ip: {0, 0, 0, 0},
          host: lan,
          dist_port: 45_200,
          loopback_dist: %{port: 45_201, proto: :inet_tcp}
        )

      {:ok, link} = Link.parse(Host.link(server))

      assert {:ok, local} =
               Client.pair(target(server, fmutate.fp), {:token, link.token}, identity())

      assert {local.host, local.dist_port, local.dist_proto} == {"127.0.0.1", 45_201, :inet_tcp}
      assert [%{dist_proto: :inet_tcp}] = Pairings.list()

      :ok = Host.renew(server)
      {:ok, link} = Link.parse(Host.link(server))
      remote = %{target(server, fmutate.fp) | host: lan}
      other = %{identity() | node: "humdinger_other@127.0.0.1"}
      assert {:ok, record} = Client.pair(remote, {:token, link.token}, other)
      assert {record.host, record.dist_port, record.dist_proto} == {lan, 45_200, :inet_tls}
      assert %{dist_proto: :inet_tls} = Pairings.get("humdinger_other@127.0.0.1")
    end

    test "plain distribution on a network address refuses to start" do
      opts = [
        service: "fmutate",
        cert: Cert.self_signed("FMutate A"),
        ip: {127, 0, 0, 1},
        dist_port: 1,
        dist_proto: :inet_tcp,
        dist_host: "192.168.1.23"
      ]

      assert {:error, {:plain_distribution_off_loopback, _}} =
               start_supervised({Host, opts})
    end
  end

  describe "requests" do
    test "a sibling can't take FMutate's node name or any fmutate_ name" do
      {server, _} = start_server([])

      for node <- ["fmutate_a@127.0.0.1", "fmutate_b@10.0.0.1"] do
        :ok = Host.renew(server)

        assert Client.pair(target(server), {:code, code(server)}, %{identity() | node: node}) ==
                 {:error, :bad_node}
      end

      assert Pairings.list() == []
    end

    test "the Allow sheet gets clean names and is told when a pairing would be replaced" do
      {server, _} = start_server(approve: {:ask, self()})

      sneaky = %{
        identity()
        | device_name: "Pixel\n7\u202E",
          app_name: "Hum\u200Bdinger\u2028\u2029this  phone"
      }

      test = self()

      spawn(fn ->
        send(test, {:first, Client.pair(target(server), {:code, code(server)}, sneaky)})
      end)

      assert_receive {:mob_pair_request, ^server, ref, request}

      assert {request.app_name, request.device_name, request.replaces} ==
               {"Humdingerthis phone", "Pixel7", nil}

      :ok = Host.decide(server, ref, :allow)
      assert_receive {:first, {:ok, _}}

      :ok = Host.renew(server)
      spawn(fn -> Client.pair(target(server), {:code, code(server)}, identity()) end)
      assert_receive {:mob_pair_request, ^server, ref, request}
      assert %{app_name: "Humdingerthis phone", device_name: "Pixel7"} = request.replaces
      :ok = Host.decide(server, ref, :deny)
    end

    test "the code, the token and the host's key stay out of status and crash reports" do
      {server, fmutate} = start_server([])
      {:ok, link} = Link.parse(Host.link(server))
      shown = inspect(:sys.get_status(server), limit: :infinity, printable_limit: :infinity)
      refute shown =~ code(server)
      refute shown =~ inspect(link.token, limit: :infinity)
      refute shown =~ inspect(fmutate.key, limit: :infinity)

      front =
        start_supervised!(
          {MobPair.Front,
           cert: fmutate, ip: {127, 0, 0, 1}, target: {{127, 0, 0, 1}, 1}, node_for_fp: & &1}
        )

      shown = inspect(:sys.get_status(front), limit: :infinity, printable_limit: :infinity)
      refute shown =~ inspect(fmutate.key, limit: :infinity)
    end
  end

  describe "the Pair screen" do
    test "info: open, then used once a sibling got in" do
      {server, _} = start_server(notify: self())
      info = Host.info(server)
      assert %{status: :open, attempts_left: 5, port: port, advertising: false} = info
      assert port == Host.port(server)
      assert {info.code, info.link} == {Host.code(server), Host.link(server)}
      assert info.expires_in in 1..300_000

      assert {:ok, _} = Client.pair(target(server), {:code, code(server)}, identity())
      assert_receive {:mob_pair_secret, ^server, :used}
      assert %{status: :used} = Host.info(server)
    end

    test "info and notify: failed attempts count down to invalid; New code reopens" do
      {server, _} = start_server(notify: self(), max_attempts: 2)
      Client.pair(target(server), {:code, "00000000"}, identity())
      assert_receive {:mob_pair_secret, ^server, :open}
      assert %{status: :open, attempts_left: 1} = Host.info(server)

      Client.pair(target(server), {:code, "00000000"}, identity())
      assert_receive {:mob_pair_secret, ^server, :invalid}
      assert %{status: :invalid, attempts_left: 0} = Host.info(server)

      :ok = Host.renew(server)
      assert_receive {:mob_pair_secret, ^server, :open}
      assert %{status: :open, attempts_left: 2} = Host.info(server)
    end

    test "info: expired once the time is up" do
      {server, _} = start_server(ttl: 50)
      Process.sleep(80)
      assert %{status: :expired, expires_in: 0} = Host.info(server)
    end

    test "the link, the default name, SRP and reserved names follow the service" do
      opts = [
        service: "magpie",
        cert: Cert.self_signed("Magpie A"),
        ip: {127, 0, 0, 1},
        host: "127.0.0.1",
        node: "magpie_a@127.0.0.1",
        dist_port: 45_124,
        approve: fn _request -> :allow end
      ]

      server = start_supervised!({Host, opts})
      assert Host.link(server) =~ ~r{\Amagpie://pair\?v=1&app=magpie&inst=a&node=magpie_a&}
      magpie = %{target(server) | service: "magpie"}

      # A sibling speaking another service's SRP can't prove the code.
      assert Client.pair(target(server), {:code, code(server)}, identity()) ==
               {:error, {:wrong_code, 4}}

      :ok = Host.renew(server)

      assert Client.pair(magpie, {:code, code(server)}, %{identity() | node: "magpie_b@1.2.3.4"}) ==
               {:error, :bad_node}

      :ok = Host.renew(server)
      assert {:ok, record} = Client.pair(magpie, {:code, code(server)}, identity())
      assert {record.service, record.name} == {"magpie", "Magpie A"}
    end

    test "a host whose mDNS port is taken runs on without advertising" do
      {:ok, taken} = :gen_udp.open(0, ip: {127, 0, 0, 1})
      {:ok, port} = :inet.port(taken)
      on_exit(fn -> :gen_udp.close(taken) end)

      {server, _} = start_server(advertise: [bind: {{127, 0, 0, 1}, port}])
      assert %{advertising: false, status: :open} = Host.info(server)
      assert {:ok, _} = Client.pair(target(server), {:code, code(server)}, identity())
    end
  end

  describe "hardening" do
    test "the endpoint listens on loopback and the link's address only" do
      lan = lan_ip()

      opts = [
        service: "fmutate",
        cert: Cert.self_signed("FMutate A"),
        node: "fmutate_a@127.0.0.1"
      ]

      opts = opts ++ [dist_port: 45_124, approve: fn _request -> :allow end]

      # no Wi-Fi in the link: nothing but loopback
      local = start_supervised!({Host, [host: "127.0.0.1"] ++ opts}, id: :local)
      {:ok, link} = Link.parse(Host.link(local))
      lan_target = %{target(local, link.fp) | host: lan}
      assert Client.pair(lan_target, {:token, link.token}, identity()) == {:error, :unreachable}
      assert {:ok, %{host: "127.0.0.1"}} = Link.parse(Host.local_link(local))

      # the link's address and loopback, on one port
      wifi = start_supervised!({Host, [host: lan] ++ opts}, id: :wifi)
      {:ok, link} = Link.parse(Host.link(wifi))
      {:ok, local_link} = Link.parse(Host.local_link(wifi))
      assert {link.host, local_link.host, local_link.token} == {lan, "127.0.0.1", link.token}
      assert {:ok, _} = Client.pair(target(wifi, link.fp), {:token, link.token}, identity())
      :ok = Host.renew(wifi)
      {:ok, link} = Link.parse(Host.link(wifi))
      lan_target = %{target(wifi, link.fp) | host: lan}
      other = %{identity() | node: "humdinger_other@127.0.0.1"}
      assert {:ok, _} = Client.pair(lan_target, {:token, link.token}, other)
    end

    test "idle connections from one address can't hold every pairing slot" do
      lan = lan_ip()
      {server, fmutate} = start_server(ip: {0, 0, 0, 0}, host: lan)

      # connections refused as busy may reset; the point is that a sibling still gets in
      idle =
        for _ <- 1..8,
            {:ok, socket} <- [:gen_tcp.connect(~c"127.0.0.1", Host.port(server), active: false)],
            do: socket

      on_exit(fn -> Enum.each(idle, &:gen_tcp.close/1) end)
      {:ok, link} = Link.parse(Host.link(server))
      remote = %{target(server, fmutate.fp) | host: lan}
      assert {:ok, _} = Client.pair(remote, {:token, link.token}, identity())
    end

    test "New code cancels an SRP exchange that started under the old code" do
      {server, _} = start_server(notify: self())
      old = code(server)
      {:ok, socket} = :ssl.connect(~c"127.0.0.1", Host.port(server), any_cert(), 5_000)
      {a_pub, _} = keys = MobPair.Srp.client_keys()
      hello = %{"type" => "hello", "v" => 1, "inst" => "a", "auth" => "srp"}
      :ok = MobPair.Wire.send(socket, Map.put(hello, "A", MobPair.Wire.b64(a_pub)))
      {:ok, %{"type" => "challenge", "salt" => salt, "B" => b}} = MobPair.Wire.recv(socket, 5_000)
      {:ok, salt} = MobPair.Wire.unb64(salt)
      {:ok, b_pub} = MobPair.Wire.unb64(b)

      :ok = Host.renew(server)
      assert_receive {:mob_pair_secret, ^server, :open}

      # a correct proof for the old code
      {:ok, key} = MobPair.Srp.client_key(old, salt, keys, b_pub, "fmutate")
      {:ok, der} = :ssl.peercert(socket)
      {:ok, binding} = MobPair.Wire.channel_binding(socket)
      fp = Cert.fingerprint(der)
      m1 = MobPair.Srp.client_proof(key, fp, binding, a_pub, b_pub, "fmutate")
      :ok = MobPair.Wire.send(socket, %{"type" => "proof", "M1" => MobPair.Wire.b64(m1)})

      assert {:ok, %{"type" => "error", "reason" => "expired"}} = MobPair.Wire.recv(socket, 5_000)
      assert %{status: :open, attempts_left: 5} = Host.info(server)
      refute_received {:mob_pair_secret, ^server, :used}
    end

    test "a token is only sent to the host the link pins" do
      {server, _} = start_server([])
      {:ok, link} = Link.parse(Host.link(server))

      assert Client.pair(target(server), {:token, link.token}, identity()) ==
               {:error, :fingerprint_required}

      assert %{status: :open, attempts_left: 5} = Host.info(server)
    end

    test "a certificate pinned for one node can't be paired under another" do
      {server, _} = start_server(approve: {:ask, self()})
      me = identity()
      spawn(fn -> Client.pair(target(server), {:code, code(server)}, me) end)
      assert_receive {:mob_pair_request, ^server, ref, %{replaces: nil}}
      :ok = Host.decide(server, ref, :allow)
      Process.sleep(100)

      :ok = Host.renew(server)
      other = %{me | node: "humdinger_other@127.0.0.1"}
      assert Client.pair(target(server), {:code, code(server)}, other) == {:error, :bad_cert}

      # the same app pairing again under its own name: the sheet says it replaces the pairing
      :ok = Host.renew(server)
      spawn(fn -> Client.pair(target(server), {:code, code(server)}, me) end)
      assert_receive {:mob_pair_request, ^server, ref, %{replaces: %{app_name: "Humdinger"}}}
      :ok = Host.decide(server, ref, :deny)
      assert [_one] = Pairings.list()
    end

    test "a node name too long for an atom is refused before Allow" do
      {server, _} = start_server([])
      pairings = Process.whereis(Pairings)
      long = %{identity() | node: "humdinger@" <> String.duplicate("a", 250)}
      assert Client.pair(target(server), {:code, code(server)}, long) == {:error, :bad_message}
      assert Process.whereis(Pairings) == pairings
      assert Pairings.list() == []
    end

    test "a name the app reserves is refused" do
      {server, _} = start_server(reserved: &(&1 == "voice@127.0.0.1"))
      voice = %{identity() | node: "voice@127.0.0.1"}
      assert Client.pair(target(server), {:code, code(server)}, voice) == {:error, :bad_node}
      :ok = Host.renew(server)
      assert {:ok, _} = Client.pair(target(server), {:code, code(server)}, identity())
    end
  end

  defp any_cert,
    do:
      [verify: :verify_peer, cacerts: [], verify_fun: Cert.verify_fun(fn _ -> true end)] ++
        MobPair.Wire.socket_options()

  test "the TLS distribution option file (FMutate's private key) is private to its owner" do
    path = Path.join(System.tmp_dir!(), "optfile_#{System.unique_integer([:positive])}.conf")
    on_exit(fn -> File.rm(path) end)
    assert Pairings.write_ssl_dist_optfile(path, Cert.self_signed("FMutate A")) == :ok
    assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o600
  end

  defp lan_ip do
    {:ok, interfaces} = :inet.getifaddrs()

    ip =
      Enum.find_value(interfaces, fn {_name, opts} ->
        Enum.find(Keyword.get_values(opts, :addr), &match?({a, _, _, _} when a != 127, &1))
      end) || flunk("needs a non-loopback IPv4 address")

    ip |> :inet.ntoa() |> List.to_string()
  end

  defp candidate(nil),
    do: %{
      name: "FMutate A",
      inst: "a",
      node: "fmutate_a@127.0.0.1",
      host: "127.0.0.1",
      port: 1,
      dist_port: nil,
      fp: <<0::256>>,
      firmware: nil,
      device: nil
    }

  defp candidate(server), do: %{candidate(nil) | port: Host.port(server)}
end
