defmodule MobPair.MixProject do
  use Mix.Project

  @source_url "https://github.com/GenericJam/mob_pair"

  def project do
    [
      app: :mob_pair,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: false,
      deps: deps(),
      aliases: aliases(),
      description:
        "Pairing and Erlang distribution between sibling Mob apps: QR link, typed code (SRP-6a), " <>
          "pinned TLS 1.3, per-peer cookies, mDNS",
      package: package(),
      docs: [main: "readme", extras: ["README.md", "DECISIONS.md"]],
      source_url: @source_url
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key, :ssl]]
  end

  defp aliases do
    [setup: ["deps.get", "cmd git config core.hooksPath .githooks"]]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:ex_slop, "~> 0.4.2", only: [:dev, :test], runtime: false},
      {:jump_credo_checks, "~> 0.1.0", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README* DECISIONS* CHANGELOG* LICENSE*)
    ]
  end
end
