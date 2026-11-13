defmodule MobPair.Code do
  @moduledoc """
  FMutate's typed pairing code: 8 Crockford base32 characters (40 bits),
  shown as `KQ7M-X2PD`.

  Typing is forgiving the Crockford way: case doesn't matter, spaces, dashes
  and dots are ignored, `I` and `L` read as `1` and `O` as `0`. `U` is not in
  the alphabet and makes a code invalid. The code is the SRP password of the
  pairing exchange (`MobPair.Srp`), always in its canonical form:
  the 8 characters, uppercase, no dash.
  """

  @alphabet ~c"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
  @length 8

  @typedoc "8 characters of the Crockford alphabet, uppercase, no separator."
  @type t :: <<_::64>>

  @doc "A fresh random code (canonical form)."
  @spec generate() :: t()
  def generate do
    for <<c::5 <- :crypto.strong_rand_bytes(5)>>, into: "", do: <<Enum.at(@alphabet, c)>>
  end

  @doc """
  The canonical form of a typed or pasted code, or `:error`.

      iex> MobPair.Code.normalize(" kq7m-x2pd ")
      {:ok, "KQ7MX2PD"}
      iex> MobPair.Code.normalize("KQ7M-X2PO")
      {:ok, "KQ7MX2P0"}
      iex> MobPair.Code.normalize("KQ7M-X2P")
      :error
  """
  @spec normalize(String.t()) :: {:ok, t()} | :error
  def normalize(input) when is_binary(input) do
    chars =
      for <<c <- String.upcase(input)>>, c not in [?\s, ?-, ?., ?\t, ?\n], do: fold(c)

    if length(chars) == @length and Enum.all?(chars, &(&1 in @alphabet)),
      do: {:ok, List.to_string(chars)},
      else: :error
  end

  def normalize(_), do: :error

  @doc ~S'The display form, `"KQ7M-X2PD"`, of a canonical code.'
  @spec format(t()) :: String.t()
  def format(<<a::binary-size(4), b::binary-size(4)>>), do: a <> "-" <> b

  defp fold(?I), do: ?1
  defp fold(?L), do: ?1
  defp fold(?O), do: ?0
  defp fold(c), do: c
end
