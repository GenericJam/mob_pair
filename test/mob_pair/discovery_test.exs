defmodule MobPair.DiscoveryTest do
  use ExUnit.Case, async: true

  alias MobPair.{Discovery, Dns, Responder}

  @fp :crypto.hash(:sha256, "fmutate cert")
  @fp_text Base.url_encode64(@fp, padding: false)
  @service ["_fmutate", "_tcp", "local"]
  @timeout 200

  defp txt(extra \\ %{}) do
    Map.merge(
      %{
        "v" => "1",
        "inst" => "a",
        "node" => "fmutate_a@192.168.1.23",
        "fp" => @fp_text,
        "port" => "45123",
        "dport" => "45200",
        "fw" => "X0X",
        "dev" => "Pixel 7"
      },
      extra
    )
  end

  defp responder(opts), do: opts |> start_responder() |> target()

  defp target(pid), do: {{127, 0, 0, 1}, Responder.port(pid)}

  defp start_responder(opts) do
    opts =
      Keyword.merge(
        [
          service: "fmutate",
          instance: "FMutate A",
          hostname: "fmutate-a.local",
          address: {192, 168, 1, 23},
          srv_port: 45_123,
          txt: txt(),
          bind: {{127, 0, 0, 1}, 0}
        ],
        opts
      )

    start_supervised!({Responder, opts}, id: make_ref())
  end

  defp browse(targets, timeout \\ @timeout),
    do: Discovery.browse(service: "fmutate", targets: targets, timeout: timeout)

  # Tests whose fake responders answer late on purpose browse for longer, so
  # a busy test run can't push the late reply past the window.
  @late_timeout 1_000

  # A responder that answers each query with `fun.(query)`, a list of
  # datagrams, from `ip` (loopback by default; another machine is played by
  # the LAN address). A reply is only taken when it echoes a query's id.
  defp fake(fun, ip \\ {127, 0, 0, 1}) do
    test = self()

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_udp.open(0, [:binary, active: true, ip: ip])
        send(test, {:fake_port, :inet.port(socket)})
        fake_loop(socket, fun)
      end)

    assert_receive {:fake_port, {:ok, port}}
    on_exit(fn -> Process.exit(pid, :kill) end)
    {ip, port}
  end

  defp fake_loop(socket, fun) do
    receive do
      {:udp, ^socket, ip, port, data} ->
        {:ok, query} = Dns.decode(data)
        Enum.each(fun.(query), &:gen_udp.send(socket, ip, port, &1))
        fake_loop(socket, fun)
    end
  end

  defp record(name, type, data), do: %{name: name, type: type, ttl: 10, data: data}

  # A legacy unicast reply to `query`: PTR to `label`, SRV to `target`, TXT
  # and (with an `address`) the target's A record.
  defp reply(query, label, txt_map, target, address) do
    name = [label | @service]

    Dns.encode_response(%{
      id: query.id,
      answers: [record(@service, :ptr, name)],
      additionals:
        [
          record(name, :srv, %{port: 1, target: target}),
          record(name, :txt, Dns.txt_strings(txt_map))
        ] ++ if(address, do: [record(target, :a, address)], else: [])
    })
  end

  defp answer(query, instance, txt_map, address \\ {10, 0, 0, 9}),
    do: reply(query, instance, txt_map, ["h", "local"], address)

  test "finds the reference responder and returns the exact candidate" do
    target = responder([])

    assert browse([target]) ==
             {:ok,
              [
                %{
                  name: "FMutate A",
                  inst: "a",
                  node: "fmutate_a@192.168.1.23",
                  host: "192.168.1.23",
                  source: "127.0.0.1",
                  port: 45_123,
                  dist_port: 45_200,
                  fp: @fp,
                  firmware: "X0X",
                  device: "Pixel 7"
                }
              ]}
  end

  test "optional keys are nil when absent or invalid; v missing counts as 1" do
    txt = txt() |> Map.drop(["v", "fw", "dev", "dport"]) |> Map.put("port", "70000")
    target = responder(txt: txt)

    assert {:ok, [candidate]} = browse([target])
    assert %{port: nil, dist_port: nil, firmware: nil, device: nil, inst: "a"} = candidate
  end

  test "update_txt changes what the next browse sees" do
    pid = start_responder([])
    :ok = Responder.update_txt(pid, Map.delete(txt(), "port"))
    assert {:ok, [%{port: nil}]} = browse([target(pid)])
  end

  test "other services, wrong versions, bad fingerprints and missing keys are dropped" do
    other = responder(service: "_other._tcp.local")
    v2 = responder(instance: "V2", txt: txt(%{"v" => "2"}))
    short_fp = responder(instance: "Short", txt: txt(%{"fp" => Base.url_encode64("x")}))
    bad_fp = responder(instance: "Bad", txt: txt(%{"fp" => "!!!"}))
    no_inst = responder(instance: "NoInst", txt: Map.delete(txt(), "inst"))
    no_node = responder(instance: "NoNode", txt: txt(%{"node" => ""}))

    assert browse([other, v2, short_fp, bad_fp, no_inst, no_node]) == {:ok, []}
  end

  test "malformed datagrams and queries are ignored next to a good answer" do
    target =
      fake(fn query ->
        [
          <<1, 2, 3>>,
          :binary.copy(<<0xFF>>, 9001),
          <<0::16, 0x8400::16, 1::16, 0::16, 0::16, 0::16, 0b11::2, 12::14, 12::16, 1::16>>,
          Dns.encode_query([%{name: @service, type: :ptr}]),
          answer(query, "FMutate A", txt())
        ]
      end)

    assert {:ok, [%{name: "FMutate A", host: "10.0.0.9"}]} = browse([target])
  end

  test "replies that don't echo a query's id are ignored" do
    target =
      fake(fn query ->
        [
          answer(%{query | id: Bitwise.bxor(query.id, 1)}, "FMutate A", txt()),
          answer(%{query | id: 0}, "FMutate A", txt())
        ]
      end)

    assert browse([target]) == {:ok, []}
  end

  # Anyone can answer with FMutate's label, fp and inst. The forged reply
  # (from another machine) reuses the genuine SRV target name, so neither
  # its PTR, SRV, TXT nor A may land on the genuine instance, whichever comes
  # first.
  for forged_first? <- [false, true] do
    test "a forged reply under the genuine label is a second candidate (forged first: #{forged_first?})" do
      {genuine_delay, forged_delay} = if unquote(forged_first?), do: {60, 0}, else: {0, 60}
      target = ["fmutate-a", "local"]
      forged_txt = txt(%{"node" => "fmutate_a@10.0.0.66", "dport" => "1", "port" => "2"})

      genuine =
        fake(fn query ->
          Process.sleep(genuine_delay)
          [reply(query, "FMutate A", txt(), target, {10, 0, 0, 1})]
        end)

      forged =
        fake(
          fn query ->
            Process.sleep(forged_delay)
            [reply(query, "FMutate A", forged_txt, target, {10, 0, 0, 66})]
          end,
          lan_ip()
        )

      assert {:ok, candidates} = browse([genuine, forged], @late_timeout)

      assert candidates |> Enum.map(&{&1.host, &1.node, &1.port, &1.dist_port}) |> Enum.sort() ==
               [
                 {"10.0.0.1", "fmutate_a@192.168.1.23", 45_123, 45_200},
                 {"10.0.0.66", "fmutate_a@10.0.0.66", 2, 1}
               ]

      assert Enum.all?(candidates, &(&1.name == "FMutate A" and &1.inst == "a" and &1.fp == @fp))
    end
  end

  test "a forged reply from another machine for the genuine host with another dport is a second candidate" do
    target = ["fmutate-a", "local"]

    genuine =
      fake(fn query -> [reply(query, "FMutate A", txt(), target, {10, 0, 0, 1})] end)

    forged =
      fake(
        fn query ->
          Process.sleep(60)
          [reply(query, "FMutate A", txt(%{"dport" => "1"}), target, {10, 0, 0, 1})]
        end,
        lan_ip()
      )

    assert {:ok, candidates} = browse([genuine, forged], @late_timeout)

    assert candidates |> Enum.map(&{&1.host, &1.dist_port}) |> Enum.sort() ==
             [{"10.0.0.1", 1}, {"10.0.0.1", 45_200}]
  end

  test "one machine answering from many ports is one source: its latest answer wins" do
    target = ["fmutate-a", "local"]

    ports =
      for dport <- ["1", "2", "3"] do
        fake(fn query ->
          Process.sleep(String.to_integer(dport) * 40)
          [reply(query, "FMutate A", txt(%{"dport" => dport}), target, {10, 0, 0, 1})]
        end)
      end

    assert {:ok, [%{dist_port: 3, source: "127.0.0.1"}]} = browse(ports, @late_timeout)
  end

  test "a flood of instance names from one machine can't crowd out another machine's" do
    flood =
      fake(fn query ->
        for n <- 1..70, do: answer(query, "Forged #{n}", txt(%{"inst" => "f#{n}"}))
      end)

    genuine =
      fake(
        fn query ->
          Process.sleep(60)
          [answer(query, "FMutate A", txt(), {10, 0, 0, 1})]
        end,
        lan_ip()
      )

    assert {:ok, candidates} = browse([flood, genuine], @late_timeout)
    assert Enum.count(candidates, &(&1.source == "127.0.0.1")) <= 4
    assert %{host: "10.0.0.1"} = Enum.find(candidates, &(&1.name == "FMutate A"))
  end

  test "a flood of replies waits in the socket, not in the browsing process's mailbox" do
    target =
      fake(fn query ->
        noise = answer(%{query | id: Bitwise.bxor(query.id, 1)}, "Noise", txt())
        [answer(query, "FMutate A", txt()) | List.duplicate(noise, 2_000)]
      end)

    test = self()
    browser = spawn_link(fn -> send(test, {:browsed, browse([target], 500)}) end)

    # one datagram at a time (plus, briefly, the port's reply to a send)
    assert max_queue(browser, 0) <= 2
    assert_receive {:browsed, {:ok, [%{name: "FMutate A"}]}}, 2_000
  end

  describe "the responder under load" do
    test "a flood of queries waits in its socket, not its mailbox" do
      pid = start_responder([])
      {_ip, port} = target(pid)
      {:ok, socket} = :gen_udp.open(0, [:binary, ip: {127, 0, 0, 1}])
      on_exit(fn -> :gen_udp.close(socket) end)
      query = Dns.encode_query([%{name: @service, type: :ptr}], 1)

      :ok = :sys.suspend(pid)
      for _ <- 1..500, do: :gen_udp.send(socket, {127, 0, 0, 1}, port, query)
      Process.sleep(100)
      {:message_queue_len, queued} = Process.info(pid, :message_queue_len)
      :ok = :sys.resume(pid)

      assert queued <= 1
    end

    test "it sends at most :max_replies replies a second" do
      pid = start_responder(max_replies: 3)
      {_ip, port} = target(pid)
      {:ok, socket} = :gen_udp.open(0, [:binary, active: true, ip: {127, 0, 0, 1}])
      on_exit(fn -> :gen_udp.close(socket) end)
      query = Dns.encode_query([%{name: @service, type: :ptr}], 1)

      for _ <- 1..6, do: :gen_udp.send(socket, {127, 0, 0, 1}, port, query)
      assert replies(socket, 300) == 3

      # the next second has its own budget
      Process.sleep(1_000)
      :gen_udp.send(socket, {127, 0, 0, 1}, port, query)
      assert replies(socket, 300) == 1
    end

    test "it serves only a local interface it is given" do
      assert {:error, {{:no_interface, {10, 255, 255, 254}}, _}} =
               start_supervised(
                 {Responder,
                  service: "fmutate",
                  instance: "FMutate A",
                  hostname: "fmutate-a.local",
                  address: {10, 255, 255, 254},
                  interface: {10, 255, 255, 254},
                  srv_port: 1,
                  bind: {{127, 0, 0, 1}, 0}}
               )
    end
  end

  defp replies(socket, wait) do
    receive do
      {:udp, ^socket, _ip, _port, _data} -> 1 + replies(socket, wait)
    after
      wait -> 0
    end
  end

  # The longest the process's mailbox got while it ran.
  defp max_queue(pid, seen) do
    case Process.info(pid, :message_queue_len) do
      {:message_queue_len, len} -> max_queue(pid, max(seen, len))
      nil -> seen
    end
  end

  defp lan_ip do
    {:ok, interfaces} = :inet.getifaddrs()

    Enum.find_value(interfaces, fn {_name, opts} ->
      Enum.find(Keyword.get_values(opts, :addr), &match?({a, _, _, _} when a != 127, &1))
    end) || flunk("needs a non-loopback IPv4 address")
  end

  test "deduplicates by fp and inst, keeps distinct instances, orders by name" do
    a = responder(instance: "FMutate A")
    a2 = responder(instance: "FMutate A (2)")
    b = responder(instance: "Beta", txt: txt(%{"inst" => "b"}))

    assert {:ok, [%{name: "Beta", inst: "b"}, %{inst: "a"}]} = browse([a, a2, b])
  end

  test "the same fp and inst at two hosts gives two candidates, so a second answer can't hide the first" do
    target =
      fake(fn query ->
        for {label, ip} <- [{"FMutate A", {10, 0, 0, 1}}, {"FMutate A (2)", {10, 0, 0, 2}}] do
          name = [label | @service]

          Dns.encode_response(%{
            id: query.id,
            answers: [record(@service, :ptr, name)],
            additionals: [
              record(name, :srv, %{port: 1, target: [String.replace(label, " ", "-"), "local"]}),
              record(name, :txt, Dns.txt_strings(txt())),
              record([String.replace(label, " ", "-"), "local"], :a, ip)
            ]
          })
        end
      end)

    assert {:ok, candidates} = browse([target])
    assert candidates |> Enum.map(& &1.host) |> Enum.sort() == ["10.0.0.1", "10.0.0.2"]
  end

  test "the latest answer for the same fp, inst and host wins" do
    target =
      fake(fn query ->
        [
          answer(query, "Old", txt(%{"fw" => "old"})),
          answer(query, "New", txt(%{"fw" => "new"}))
        ]
      end)

    assert {:ok, [%{name: "New", firmware: "new"}]} = browse([target])
  end

  test "asks for SRV, TXT and A when the PTR answer comes alone" do
    instance = ["FMutate A" | @service]

    target =
      fake(fn %{questions: questions} = query ->
        Enum.map(questions, fn
          %{type: :ptr} ->
            Dns.encode_response(%{id: query.id, answers: [record(@service, :ptr, instance)]})

          %{type: :srv} ->
            srv = %{port: 1, target: ["far", "local"]}
            Dns.encode_response(%{id: query.id, answers: [record(instance, :srv, srv)]})

          %{type: :txt} ->
            txt = Dns.txt_strings(txt())
            Dns.encode_response(%{id: query.id, answers: [record(instance, :txt, txt)]})

          %{type: :a} ->
            a = record(["far", "local"], :a, {10, 1, 2, 3})
            Dns.encode_response(%{id: query.id, answers: [a]})
        end)
      end)

    assert {:ok, [%{name: "FMutate A", host: "10.1.2.3", inst: "a"}]} = browse([target])
  end

  test "host falls back to the reply's source address without an A record" do
    target = fake(fn query -> [answer(query, "FMutate A", txt(), nil)] end)
    assert {:ok, [%{host: "127.0.0.1"}]} = browse([target])
  end

  test "returns after the timeout when nothing answers" do
    {:ok, silent} = :gen_udp.open(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(silent)
    started = System.monotonic_time(:millisecond)

    assert Discovery.browse(service: "fmutate", targets: [{{127, 0, 0, 1}, port}], timeout: 100) ==
             {:ok, []}

    # At least the window; the upper bound only says it doesn't hang (a busy
    # host can be slow to schedule the return).
    assert (System.monotonic_time(:millisecond) - started) in 100..1_000
  end
end
