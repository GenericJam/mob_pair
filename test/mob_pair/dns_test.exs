defmodule MobPair.DnsTest do
  use ExUnit.Case, async: true

  alias MobPair.Dns

  @instance ["FMutate A.1", "_fmutate", "_tcp", "local"]

  defp response do
    %{
      id: 77,
      questions: [%{name: ["_fmutate", "_tcp", "local"], type: :ptr, qu: false}],
      answers: [
        %{
          name: ["_fmutate", "_tcp", "local"],
          type: :ptr,
          cache_flush: false,
          ttl: 120,
          data: @instance
        }
      ],
      additionals: [
        %{
          name: @instance,
          type: :srv,
          cache_flush: true,
          ttl: 120,
          data: %{priority: 1, weight: 2, port: 45_123, target: ["fmutate-a", "local"]}
        },
        %{
          name: @instance,
          type: :txt,
          cache_flush: true,
          ttl: 120,
          data: ["v=1", "inst=a", String.duplicate("x", 255)]
        },
        %{
          name: ["fmutate-a", "local"],
          type: :a,
          cache_flush: true,
          ttl: 10,
          data: {10, 0, 0, 7}
        },
        %{name: ["fmutate-a", "local"], type: 99, cache_flush: false, ttl: 1, data: <<1, 2, 3>>}
      ]
    }
  end

  test "a query round-trips with the QU bit and dotted names" do
    packet =
      Dns.encode_query(
        [%{name: "_fmutate._tcp.local", type: :ptr, qu: true}, %{name: @instance, type: :any}],
        513
      )

    assert {:ok, message} = Dns.decode(packet)
    refute Dns.response?(message)
    assert message.id == 513

    assert message.questions == [
             %{name: ["_fmutate", "_tcp", "local"], type: :ptr, qu: true},
             %{name: @instance, type: :any, qu: false}
           ]
  end

  test "a response round-trips every record type, labels keep dots and spaces" do
    assert {:ok, message} = response() |> Dns.encode_response() |> Dns.decode()
    assert Dns.response?(message)
    assert message.flags == 0x8400
    assert message.authorities == []
    assert Map.take(message, [:id, :questions, :answers, :additionals]) == response()
  end

  test "an empty TXT record is one empty string on the wire and decodes to []" do
    record = %{name: @instance, type: :txt, ttl: 1, data: []}
    packet = Dns.encode_response(%{answers: [record]})
    assert binary_part(packet, byte_size(packet) - 3, 3) == <<0, 1, 0>>
    assert {:ok, %{answers: [%{data: []}]}} = Dns.decode(packet)
  end

  test "decodes compressed names" do
    # Question "_fmutate._tcp.local" at 12; the answer's name points to it
    # and its PTR data is "FMutate A" + a pointer to the same name.
    question = <<8, "_fmutate", 4, "_tcp", 5, "local", 0, 12::16, 1::16>>
    rdata = <<9, "FMutate A", 0b11::2, 12::14>>

    packet =
      <<0::16, 0x8400::16, 1::16, 1::16, 0::16, 0::16>> <>
        question <> <<0b11::2, 12::14, 12::16, 1::16, 120::32, byte_size(rdata)::16>> <> rdata

    assert {:ok, %{answers: [answer]}} = Dns.decode(packet)
    assert answer.name == ["_fmutate", "_tcp", "local"]
    assert answer.data == ["FMutate A", "_fmutate", "_tcp", "local"]
  end

  describe "hostile input" do
    defp header(qd, an \\ 0, ns \\ 0, ar \\ 0),
      do: <<0::16, 0::16, qd::16, an::16, ns::16, ar::16>>

    test "a pointer to itself, a forward pointer and a pointer loop are rejected" do
      assert Dns.decode(header(1) <> <<0b11::2, 12::14, 12::16, 1::16>>) == {:error, :bad_pointer}

      assert Dns.decode(header(1) <> <<0b11::2, 20::14, 12::16, 1::16, 1, "a", 0>>) ==
               {:error, :bad_pointer}

      # "a" then a pointer back to "a": each jump lands where it started.
      assert Dns.decode(header(1) <> <<1, "a", 0b11::2, 12::14, 12::16, 1::16>>) ==
               {:error, :bad_pointer}
    end

    test "every truncation of a valid response is an error" do
      packet = Dns.encode_response(response())

      for size <- 0..(byte_size(packet) - 1) do
        assert {:error, _} = Dns.decode(binary_part(packet, 0, size))
      end
    end

    test "oversize section counts and datagrams are rejected" do
      assert Dns.decode(header(65)) == {:error, :too_many_records}
      assert Dns.decode(header(0, 0, 0, 0xFFFF)) == {:error, :too_many_records}
      assert Dns.decode(header(0) <> :binary.copy(<<0>>, 9000)) == {:error, :too_large}
    end

    test "reserved label types, non-UTF-8 labels and names over 255 bytes are rejected" do
      assert Dns.decode(header(1) <> <<0b01::2, 5::6, "abcde", 0, 12::16, 1::16>>) ==
               {:error, :bad_label}

      assert Dns.decode(header(1) <> <<0b10::2, 5::6, "abcde", 0, 12::16, 1::16>>) ==
               {:error, :bad_label}

      assert Dns.decode(header(1) <> <<2, 0xFF, 0xFE, 0, 12::16, 1::16>>) == {:error, :bad_label}

      long = :binary.copy(<<63, String.duplicate("a", 63)::binary>>, 4)
      assert Dns.decode(header(1) <> long <> <<0, 12::16, 1::16>>) == {:error, :bad_name}
    end

    test "rdata that disagrees with its length is rejected" do
      a = <<1, "h", 0, 1::16, 1::16, 0::32, 3::16, 1, 2, 3>>
      assert Dns.decode(header(0, 1) <> a) == {:error, :bad_rdata}

      txt = <<1, "h", 0, 16::16, 1::16, 0::32, 3::16, 5, "ab">>
      assert Dns.decode(header(0, 1) <> txt) == {:error, :bad_rdata}

      ptr = <<1, "h", 0, 12::16, 1::16, 0::32, 4::16, 1, "x", 0, 0>>
      assert Dns.decode(header(0, 1) <> ptr) == {:error, :bad_rdata}
    end

    test "random and mutated datagrams never raise" do
      packet = Dns.encode_response(response())
      :rand.seed(:exsss, {1, 2, 3})

      for _ <- 1..2000 do
        random = :crypto.strong_rand_bytes(:rand.uniform(200))
        position = :rand.uniform(byte_size(packet)) - 1
        <<before::binary-size(^position), _, rest::binary>> = packet
        mutated = <<before::binary, :rand.uniform(256) - 1, rest::binary>>

        for input <- [random, header(1, 1, 0, 1) <> random, mutated] do
          assert match?({:ok, _}, Dns.decode(input)) or match?({:error, _}, Dns.decode(input))
        end
      end
    end
  end

  test "encoding rejects oversized labels, names and TXT strings" do
    assert_raise ArgumentError, fn ->
      Dns.encode_query([%{name: [String.duplicate("a", 64), "local"], type: :a}])
    end

    assert_raise ArgumentError, fn ->
      Dns.encode_query([%{name: List.duplicate(String.duplicate("a", 63), 4), type: :a}])
    end

    assert_raise ArgumentError, fn ->
      Dns.encode_response(%{
        answers: [%{name: "x.local", type: :txt, data: [String.duplicate("a", 256)]}]
      })
    end
  end

  test "TXT strings to a map: lowercased keys, first wins, junk skipped" do
    assert Dns.txt_map(["V=1", "v=2", "node=a@b=c", "flag", "=x", <<0xFF, "=1">>, "fw="]) ==
             %{"v" => "1", "node" => "a@b=c", "fw" => ""}

    assert Dns.txt_strings(%{"v" => "1", "inst" => "a"}) == ["inst=a", "v=1"]
  end
end
