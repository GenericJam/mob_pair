defmodule MobPair.CodeAndLinkTest do
  use ExUnit.Case, async: true

  alias MobPair.{Join, Link}
  alias MobPair.Code, as: PairCode

  doctest MobPair.Code

  describe "codes" do
    test "generated codes are 8 Crockford characters and survive display and retyping" do
      codes = for _ <- 1..200, do: PairCode.generate()
      assert Enum.all?(codes, &(&1 =~ ~r/\A[0-9A-HJKMNP-TV-Z]{8}\z/))

      assert Enum.map(codes, &PairCode.normalize(PairCode.format(&1))) ==
               Enum.map(codes, &{:ok, &1})

      assert Enum.map(codes, &PairCode.normalize(String.downcase(PairCode.format(&1)))) ==
               Enum.map(codes, &{:ok, &1})
    end

    test "typing is forgiving: separators, case, I/L for 1 and O for 0" do
      assert Join.normalize_code("kq7m x2pd") == {:ok, "KQ7M-X2PD"}
      assert Join.normalize_code("KQ7M.X2PD\n") == {:ok, "KQ7M-X2PD"}
      assert Join.normalize_code("iL0o-0000") == {:ok, "1100-0000"}
    end

    test "wrong lengths, U and other characters are rejected" do
      for bad <- [
            "",
            "KQ7M-X2P",
            "KQ7M-X2PDD",
            "KQ7M-X2PU",
            "KQ7M-X2P!",
            "KQ7M_X2PD",
            "ＫQ7M-X2PD"
          ] do
        assert Join.normalize_code(bad) == {:error, :invalid_code}, inspect(bad)
      end
    end
  end

  describe "pairing links" do
    setup do
      fields = %{
        service: "fmutate",
        inst: "a",
        node: "fmutate_a",
        host: "192.168.1.23",
        port: 45_123,
        fp: :crypto.strong_rand_bytes(32),
        token: :crypto.strong_rand_bytes(16)
      }

      %{fields: fields, link: Link.build(fields)}
    end

    test "a built link parses back to the same offer", %{fields: fields, link: link} do
      assert {:ok, offer} = Link.parse(link, services: ["fmutate"])
      assert offer == Map.put(fields, :via, :link)
    end

    test "surrounding whitespace from a paste is ignored", %{link: link} do
      assert {:ok, _} = Link.parse("  " <> link <> "\n")
    end

    test "the scheme is the service; other services are refused when a list is given",
         %{fields: fields} do
      magpie = Link.build(%{fields | service: "magpie", node: "magpie_a"})
      assert magpie =~ ~r{\Amagpie://pair\?v=1&app=magpie&}
      assert {:ok, %{service: "magpie", node: "magpie_a"}} = Link.parse(magpie)
      assert Link.parse(magpie, services: ["fmutate"]) == {:error, :not_a_pairing_link}

      assert {:ok, %{service: "magpie"}} =
               Link.parse(String.replace_prefix(magpie, "magpie", "MAGPIE"))
    end

    test "app and inst may be absent; app must match the scheme", %{link: link} do
      bare = link |> String.replace("app=fmutate&", "") |> String.replace("inst=a&", "")
      assert {:ok, %{service: "fmutate", inst: "a"}} = Link.parse(bare)

      assert Link.parse(String.replace(link, "app=fmutate", "app=magpie")) ==
               {:error, {:invalid, :app}}
    end

    test "every field is checked", %{link: link} do
      cases = [
        {"https://pair?v=1", :not_a_pairing_link},
        {"fmutate://unpair?v=1", :not_a_pairing_link},
        {"not a link", :not_a_pairing_link},
        {String.replace(link, "v=1", "v=2"), :unsupported_version},
        {String.replace(link, "inst=a", "inst=ab"), {:invalid, :inst}},
        {String.replace(link, "node=fmutate_a", "node=Evil"), {:invalid, :node}},
        {String.replace(link, "host=192.168.1.23", "host=example.com"), {:invalid, :host}},
        {String.replace(link, "port=45123", "port=70000"), {:invalid, :port}},
        {Regex.replace(~r/fp=[^&]+/, link, "fp=AAAA"), {:invalid, :fp}},
        {Regex.replace(~r/&t=[^&]+/, link, ""), {:missing, :token}}
      ]

      for {bad, reason} <- cases do
        assert Link.parse(bad, services: ["fmutate"]) == {:error, reason}, bad
      end
    end

    # What Humdinger's own parser (before it moves to this package) requires.
    test "an fmutate link carries every field FMutate v1 parsers read", %{fields: f, link: link} do
      assert %URI{scheme: "fmutate", host: "pair", path: nil, query: query} = URI.parse(link)
      q = URI.decode_query(query)
      assert q["v"] == "1"
      assert q["inst"] == "a"
      assert q["node"] =~ ~r/\Afmutate_[a-z0-9_]{1,32}\z/
      assert {q["host"], q["port"]} == {"192.168.1.23", "45123"}
      assert Base.url_decode64(q["fp"], padding: false) == {:ok, f.fp}
      assert Base.url_decode64(q["t"], padding: false) == {:ok, f.token}
    end
  end
end
