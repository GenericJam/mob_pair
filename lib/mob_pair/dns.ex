defmodule MobPair.Dns do
  @moduledoc """
  The DNS message codec for FMutate discovery (multicast DNS, RFC 6762, with
  DNS-SD records, RFC 6763). Both sides use it: `MobPair.Discovery`
  (the browser) and `MobPair.Responder`.

  ## Data

  A name is a list of labels: `["FMutate A", "_fmutate", "_tcp", "local"]`.
  Labels are UTF-8 binaries and may contain dots and spaces (DNS-SD instance
  names do), so a name is never a dotted string once decoded. Encoding
  functions also take a dotted string (`"_fmutate._tcp.local"`), split on
  dots; pass a label list when a label contains a dot. Names compare ASCII
  case-insensitively (`name_key/1`).

  A message:

      %{
        id: 0..65535,
        flags: 0..65535,          # QR is bit 15 (`response?/1`)
        questions: [question],
        answers: [record],
        authorities: [record],
        additionals: [record]
      }

  A question: `%{name: [label], type: type, qu: boolean}`, where `qu` is the
  mDNS "unicast response requested" bit (top bit of the class).

  A record: `%{name: [label], type: type, cache_flush: boolean, ttl:
  non_neg_integer, data: data}`, where `cache_flush` is the mDNS top bit of
  the class (set on unique records). `data` by type:

    * `:a` – `{a, b, c, d}`
    * `:ptr` – a name
    * `:srv` – `%{priority: p, weight: w, port: port, target: name}`
    * `:txt` – a list of binaries, each at most 255 bytes (`txt_map/1`,
      `txt_strings/1` convert to and from DNS-SD key/value pairs)
    * any other type – the raw rdata binary

  `type` is `:a`, `:ptr`, `:txt`, `:aaaa`, `:srv`, `:nsec`, `:any` or the
  numeric type for the rest. The class is always IN (1); other classes are
  decoded with the same shape.

  ## Hostile input

  `decode/1` takes untrusted datagrams and returns `{:error, reason}` for
  anything malformed: datagrams over 9000 bytes (the mDNS maximum), more
  than 64 entries in a section, truncated headers, records or rdata,
  compression pointers that do not point strictly before the name segment
  they occur in (which also rules out loops), more than 32 pointer jumps,
  labels over 63 bytes or not UTF-8, the reserved label types, and names
  over 255 bytes. Bytes after the last section are ignored.
  """

  import Bitwise

  @max_datagram 9000
  @max_section 64
  @max_jumps 32
  @max_label 63
  @max_name 255

  @types %{
    1 => :a,
    12 => :ptr,
    16 => :txt,
    28 => :aaaa,
    33 => :srv,
    47 => :nsec,
    255 => :any
  }
  @type_codes Map.new(@types, fn {code, type} -> {type, code} end)

  @class_in 1
  @flags_response 0x8400

  @type label :: String.t()
  @type name :: [label()]
  @type type :: :a | :ptr | :txt | :aaaa | :srv | :nsec | :any | non_neg_integer()
  @type question :: %{name: name(), type: type(), qu: boolean()}
  @type srv :: %{
          priority: non_neg_integer(),
          weight: non_neg_integer(),
          port: :inet.port_number(),
          target: name()
        }
  @type resource :: %{
          name: name(),
          type: type(),
          cache_flush: boolean(),
          ttl: non_neg_integer(),
          data: :inet.ip4_address() | name() | srv() | [binary()] | binary()
        }
  @type message :: %{
          id: non_neg_integer(),
          flags: non_neg_integer(),
          questions: [question()],
          answers: [resource()],
          authorities: [resource()],
          additionals: [resource()]
        }

  @typedoc "A name to encode: a label list or a dotted string."
  @type name_input :: name() | String.t()

  @doc "Splits a dotted name into labels; a label list is returned unchanged."
  @spec name(name_input()) :: name()
  def name(labels) when is_list(labels), do: labels
  def name(dotted) when is_binary(dotted), do: String.split(dotted, ".", trim: true)

  @doc "A comparison key for a name: its labels lowercased (ASCII only, as DNS does)."
  @spec name_key(name_input()) :: [binary()]
  def name_key(name), do: Enum.map(name(name), &String.downcase(&1, :ascii))

  @doc "Whether a decoded message is a response (QR bit set)."
  @spec response?(message()) :: boolean()
  def response?(%{flags: flags}), do: (flags &&& 0x8000) != 0

  @doc """
  Encodes a query. Each question is `%{name:, type:}` with an optional `qu:`
  (default false). Multicast queries use id 0; a legacy unicast query may
  use any id, which the responder echoes.
  """
  @spec encode_query([map()], non_neg_integer()) :: binary()
  def encode_query(questions, id \\ 0) do
    encode(%{id: id, flags: 0, questions: questions})
  end

  @doc """
  Encodes an authoritative response (flags QR + AA). Takes `:answers` and
  optionally `:additionals`, `:id` (default 0) and `:questions` (a legacy
  unicast reply echoes the query's id and questions).
  """
  @spec encode_response(map()) :: binary()
  def encode_response(response) do
    encode(Map.put(response, :flags, @flags_response))
  end

  @doc """
  Encodes a message (the shape `decode/1` returns; missing sections are
  empty, missing `:id` and `:flags` are 0, records default to `ttl: 120`
  and `cache_flush: false`). Names are written without compression. Raises
  `ArgumentError` for labels over 63 bytes, names over 255 bytes or TXT
  strings over 255 bytes.
  """
  @spec encode(map()) :: binary()
  def encode(message) do
    questions = Map.get(message, :questions, [])
    answers = Map.get(message, :answers, [])
    authorities = Map.get(message, :authorities, [])
    additionals = Map.get(message, :additionals, [])

    IO.iodata_to_binary([
      <<Map.get(message, :id, 0)::16, Map.get(message, :flags, 0)::16, length(questions)::16,
        length(answers)::16, length(authorities)::16, length(additionals)::16>>,
      Enum.map(questions, &encode_question/1),
      Enum.map(answers, &encode_record/1),
      Enum.map(authorities, &encode_record/1),
      Enum.map(additionals, &encode_record/1)
    ])
  end

  defp encode_question(question) do
    qu = if Map.get(question, :qu, false), do: 0x8000, else: 0

    [
      encode_name(question.name),
      <<type_code(question.type)::16, bor(@class_in, qu)::16>>
    ]
  end

  defp encode_record(record) do
    flush = if Map.get(record, :cache_flush, false), do: 0x8000, else: 0
    rdata = IO.iodata_to_binary(encode_rdata(record.type, record.data))

    [
      encode_name(record.name),
      <<type_code(record.type)::16, bor(@class_in, flush)::16, Map.get(record, :ttl, 120)::32,
        byte_size(rdata)::16>>,
      rdata
    ]
  end

  defp encode_rdata(:a, {a, b, c, d}), do: <<a, b, c, d>>
  defp encode_rdata(:ptr, name), do: encode_name(name)

  defp encode_rdata(:srv, srv) do
    [
      <<Map.get(srv, :priority, 0)::16, Map.get(srv, :weight, 0)::16, srv.port::16>>,
      encode_name(srv.target)
    ]
  end

  defp encode_rdata(:txt, []), do: <<0>>

  defp encode_rdata(:txt, strings) do
    Enum.map(strings, fn string ->
      if byte_size(string) > 255,
        do: raise(ArgumentError, "TXT string over 255 bytes: #{inspect(string)}")

      [byte_size(string), string]
    end)
  end

  defp encode_rdata(_type, raw) when is_binary(raw), do: raw

  defp encode_name(name) do
    wire =
      IO.iodata_to_binary([
        Enum.map(name(name), fn label ->
          if byte_size(label) not in 1..@max_label,
            do: raise(ArgumentError, "label must be 1..63 bytes: #{inspect(label)}")

          [byte_size(label), label]
        end),
        0
      ])

    if byte_size(wire) > @max_name,
      do: raise(ArgumentError, "name over 255 bytes: #{inspect(name)}")

    wire
  end

  defp type_code(type) when is_integer(type), do: type
  defp type_code(type), do: Map.fetch!(@type_codes, type)

  @doc """
  Decodes a datagram. Returns `{:error, reason}` for malformed or oversized
  input (see the moduledoc); never raises on any binary.
  """
  @spec decode(binary()) :: {:ok, message()} | {:error, atom()}
  def decode(msg) when byte_size(msg) > @max_datagram, do: {:error, :too_large}

  def decode(<<id::16, flags::16, qd::16, an::16, ns::16, ar::16, _::binary>> = msg) do
    with :ok <- check_counts([qd, an, ns, ar]),
         {:ok, questions, off} <- decode_many(msg, 12, qd, &decode_question/2),
         {:ok, answers, off} <- decode_many(msg, off, an, &decode_record/2),
         {:ok, authorities, off} <- decode_many(msg, off, ns, &decode_record/2),
         {:ok, additionals, _off} <- decode_many(msg, off, ar, &decode_record/2) do
      {:ok,
       %{
         id: id,
         flags: flags,
         questions: questions,
         answers: answers,
         authorities: authorities,
         additionals: additionals
       }}
    end
  end

  def decode(msg) when is_binary(msg), do: {:error, :truncated}

  defp check_counts(counts) do
    if Enum.all?(counts, &(&1 <= @max_section)), do: :ok, else: {:error, :too_many_records}
  end

  defp decode_many(msg, off, count, fun), do: decode_many(msg, off, count, fun, [])

  defp decode_many(_msg, off, 0, _fun, acc), do: {:ok, Enum.reverse(acc), off}

  defp decode_many(msg, off, count, fun, acc) do
    case fun.(msg, off) do
      {:ok, item, off} -> decode_many(msg, off, count - 1, fun, [item | acc])
      error -> error
    end
  end

  defp decode_question(msg, off) do
    with {:ok, name, off} <- decode_name(msg, off) do
      case msg do
        <<_::binary-size(^off), type::16, qu::1, _class::15, _::binary>> ->
          {:ok, %{name: name, type: type_atom(type), qu: qu == 1}, off + 4}

        _ ->
          {:error, :truncated}
      end
    end
  end

  defp decode_record(msg, off) do
    with {:ok, name, off} <- decode_name(msg, off),
         {:ok, type, flush, ttl, rd_off, rd_len} <- record_header(msg, off),
         {:ok, data} <- decode_rdata(type_atom(type), msg, rd_off, rd_len) do
      record = %{name: name, type: type_atom(type), cache_flush: flush, ttl: ttl, data: data}
      {:ok, record, rd_off + rd_len}
    end
  end

  defp record_header(msg, off) do
    case msg do
      <<_::binary-size(^off), type::16, flush::1, _class::15, ttl::32, rd_len::16,
        _::binary-size(rd_len), _::binary>> ->
        {:ok, type, flush == 1, ttl, off + 10, rd_len}

      _ ->
        {:error, :truncated}
    end
  end

  defp decode_rdata(:a, msg, off, 4) do
    <<_::binary-size(^off), a, b, c, d, _::binary>> = msg
    {:ok, {a, b, c, d}}
  end

  defp decode_rdata(:a, _msg, _off, _len), do: {:error, :bad_rdata}

  defp decode_rdata(:ptr, msg, off, len) do
    case decode_name(msg, off) do
      {:ok, name, next} when next == off + len -> {:ok, name}
      {:ok, _name, _next} -> {:error, :bad_rdata}
      error -> error
    end
  end

  defp decode_rdata(:srv, msg, off, len) when len >= 7 do
    <<_::binary-size(^off), priority::16, weight::16, port::16, _::binary>> = msg

    case decode_name(msg, off + 6) do
      {:ok, target, next} when next == off + len ->
        {:ok, %{priority: priority, weight: weight, port: port, target: target}}

      {:ok, _target, _next} ->
        {:error, :bad_rdata}

      error ->
        error
    end
  end

  defp decode_rdata(:srv, _msg, _off, _len), do: {:error, :bad_rdata}

  defp decode_rdata(:txt, msg, off, len) do
    <<_::binary-size(^off), rdata::binary-size(^len), _::binary>> = msg
    decode_txt(rdata, [])
  end

  defp decode_rdata(_type, msg, off, len) do
    <<_::binary-size(^off), rdata::binary-size(^len), _::binary>> = msg
    {:ok, rdata}
  end

  # An empty TXT record is one empty string on the wire; it decodes to [].
  defp decode_txt(<<>>, [""]), do: {:ok, []}
  defp decode_txt(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_txt(<<len, string::binary-size(len), rest::binary>>, acc),
    do: decode_txt(rest, [string | acc])

  defp decode_txt(_rest, _acc), do: {:error, :bad_rdata}

  # Reads a possibly compressed name at `off`. Returns the offset just past
  # the name where it started (after the first pointer, if any). Each
  # pointer must point before the start of the segment it occurs in, so the
  # walk only ever moves backwards and terminates.
  defp decode_name(msg, off), do: read_name(msg, off, off, [], 1, 0, nil)

  defp read_name(msg, off, segment, labels, wire_len, jumps, resume) do
    case msg do
      <<_::binary-size(^off), 0, _::binary>> ->
        {:ok, Enum.reverse(labels), resume || off + 1}

      <<_::binary-size(^off), 0b11::2, ptr::14, _::binary>> ->
        jump(msg, ptr, segment, labels, wire_len, jumps, resume || off + 2)

      <<_::binary-size(^off), 0b00::2, len::6, label::binary-size(len), _::binary>> ->
        add_label(
          msg,
          off + 1 + len,
          segment,
          [label | labels],
          wire_len + len + 1,
          jumps,
          resume
        )

      <<_::binary-size(^off), kind::2, _::6, _::binary>> when kind in [0b01, 0b10] ->
        {:error, :bad_label}

      _ ->
        {:error, :truncated}
    end
  end

  defp jump(_msg, ptr, segment, _labels, _wire_len, jumps, _resume)
       when ptr >= segment or jumps >= @max_jumps,
       do: {:error, :bad_pointer}

  defp jump(msg, ptr, _segment, labels, wire_len, jumps, resume),
    do: read_name(msg, ptr, ptr, labels, wire_len, jumps + 1, resume)

  defp add_label(_msg, _off, _segment, _labels, wire_len, _jumps, _resume)
       when wire_len > @max_name,
       do: {:error, :bad_name}

  defp add_label(msg, off, segment, [label | _] = labels, wire_len, jumps, resume) do
    if String.valid?(label),
      do: read_name(msg, off, segment, labels, wire_len, jumps, resume),
      else: {:error, :bad_label}
  end

  defp type_atom(code), do: Map.get(@types, code, code)

  @doc """
  DNS-SD TXT strings to a map (RFC 6763 §6). Keys are lowercased (ASCII);
  the first occurrence of a key wins; strings without `=`, with an empty
  key, or that are not UTF-8 are skipped.
  """
  @spec txt_map([binary()]) :: %{String.t() => String.t()}
  def txt_map(strings) do
    Enum.reduce(strings, %{}, fn string, acc ->
      with true <- String.valid?(string),
           [key, value] when key != "" <- String.split(string, "=", parts: 2) do
        Map.put_new(acc, String.downcase(key, :ascii), value)
      else
        _ -> acc
      end
    end)
  end

  @doc "A map of TXT keys and values to `key=value` strings, sorted by key."
  @spec txt_strings(%{String.t() => String.t()}) :: [binary()]
  def txt_strings(map) do
    map |> Enum.sort() |> Enum.map(fn {key, value} -> key <> "=" <> value end)
  end
end
