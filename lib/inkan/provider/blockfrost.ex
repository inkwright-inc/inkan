defmodule Inkan.Provider.Blockfrost do
  @moduledoc """
  `Inkan.Provider` backed by the Blockfrost API.

  Requires the optional `:req` dependency. Configure with:

      config = Inkan.Provider.Blockfrost.config("preprodAbC...", :preprod)

  The network is inferred from nothing — it is always explicit, because a
  transaction built for one network and submitted to another is the kind of
  mistake a library should make unrepresentable.

  `req_options` in the config merges into every request; tests use it to
  route through `Req.Test`.
  """

  @behaviour Inkan.Provider

  @base_urls %{
    mainnet: "https://cardano-mainnet.blockfrost.io/api/v0",
    preprod: "https://cardano-preprod.blockfrost.io/api/v0",
    preview: "https://cardano-preview.blockfrost.io/api/v0"
  }

  @doc "Builds a config map for the given project id and network."
  def config(project_id, network, req_options \\ [])
      when is_binary(project_id) and is_map_key(@base_urls, network) do
    %{project_id: project_id, network: network, req_options: req_options}
  end

  @impl true
  def protocol_params(config) do
    with {:ok, params} <- get(config, "/epochs/latest/parameters"),
         {:ok, block} <- get(config, "/blocks/latest") do
      {:ok,
       %{
         min_fee_a: params["min_fee_a"],
         min_fee_b: params["min_fee_b"],
         slot: block["slot"]
       }}
    end
  end

  @impl true
  def utxos(config, address) do
    with {:ok, utxos} <- get(config, "/addresses/#{address}/utxos") do
      spendable =
        for utxo <- utxos,
            # ADA-only, no inline datum / script ref: anything fancier is
            # excluded so spending it can't destroy what we don't model.
            utxo["inline_datum"] == nil,
            utxo["reference_script_hash"] == nil,
            match?([%{"unit" => "lovelace"}], utxo["amount"]) do
          [%{"quantity" => quantity}] = utxo["amount"]

          %{
            tx_id: utxo["tx_hash"],
            index: utxo["output_index"],
            lovelace: String.to_integer(quantity)
          }
        end

      {:ok, spendable}
    end
  end

  @impl true
  def submit(config, tx_cbor) when is_binary(tx_cbor) do
    request(config)
    |> req().post(
      url: "/tx/submit",
      headers: [{"content-type", "application/cbor"}],
      body: tx_cbor
    )
    |> case do
      {:ok, %{status: 200, body: tx_id}} when is_binary(tx_id) ->
        {:ok, String.trim(tx_id, "\"")}

      {:ok, %{status: status, body: body}} ->
        {:error, {:blockfrost, status, body}}

      {:error, exception} ->
        {:error, exception}
    end
  end

  @impl true
  def tx_status(config, tx_id) do
    case get(config, "/txs/#{tx_id}") do
      {:ok, %{"block_height" => height, "block_time" => time}} ->
        {:confirmed, %{block_height: height, block_time: DateTime.from_unix!(time)}}

      {:error, {:blockfrost, 404, _body}} ->
        :pending

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp get(config, path) do
    case req().get(request(config), url: path) do
      {:ok, %{status: 200, body: body}} -> {:ok, body}
      {:ok, %{status: status, body: body}} -> {:error, {:blockfrost, status, body}}
      {:error, exception} -> {:error, exception}
    end
  end

  defp request(%{project_id: project_id, network: network, req_options: req_options}) do
    req().new(
      [
        base_url: Map.fetch!(@base_urls, network),
        headers: [{"project_id", project_id}],
        retry: false
      ] ++ req_options
    )
  end

  # Indirection so a missing optional dep fails with a clear message
  # instead of an UndefinedFunctionError deep in a request.
  defp req do
    Code.ensure_loaded?(Req) ||
      raise """
      Inkan.Provider.Blockfrost requires the optional :req dependency.
      Add {:req, "~> 0.5"} to your deps, or implement Inkan.Provider
      with your own HTTP client.
      """

    Req
  end
end
