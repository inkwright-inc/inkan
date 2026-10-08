defmodule Inkan.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/inkwright/inkan"

  def project do
    [
      app: :inkan,
      version: @version,
      elixir: "~> 1.15",
      elixirc_options: [warnings_as_errors: true],
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Inkan",
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url
    ]
  end

  def application do
    [
      extra_applications: [:crypto]
    ]
  end

  defp description do
    """
    Build, sign, and submit Cardano transactions from Elixir — payments and
    on-chain metadata, from a mnemonic wallet, via Blockfrost. Narrow by
    design, verified against reference implementations.
    """
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      maintainers: ["Clinton De Young"]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md"],
      source_ref: "v#{@version}"
    ]
  end

  defp deps do
    [
      {:blake2, "~> 1.0"},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:stream_data, "~> 1.0", only: [:dev, :test]}
    ]
  end
end
