defmodule Dredd.Plug.Token do
  @moduledoc false

  use Plug.ErrorHandler
  use Plug.Router

  alias Dredd.OAuth.{Client, Grant}
  alias Grant.AuthorizationCode
  alias Plug.Conn

  import Dredd.Plug.Utils

  require Logger

  plug Plug.Parsers,
    parsers: [:urlencoded]

  plug :match
  plug :dispatch

  post "/" do
    %Conn{private: %{server: server}, body_params: params} = conn

    with {:ok, grant} <- grant(params),
         {:ok, client_id} <- fetch_param(params, "client_id"),
         {:ok, client} <- server.client(client_id),
         {:ok, redirect_uri} <- fetch_param(params, "redirect_uri"),
         :ok <- Client.validate_redirect_uri(client, redirect_uri),
         {:ok, token} <- Grant.token(grant, server, client, params) do
      send_token_response(conn, :ok, token)
    else
      {:error, reason} ->
        send_token_response(conn, :bad_request, %{"error" => reason})
    end
  end

  match "/",
    do: send_response(conn, :method_not_allowed, "text/plain", "")

  match _, do: send_response(conn, :not_found, "text/plain", "")

  defp handle_errors(conn, error) do
    Logger.error(fn -> "Error handling request: #{inspect(error)}" end)
    send_response(conn, :internal_server_error, "text/plain", "")
  end

  defp grant(%{"grant_type" => "authorization_code"}),
    do: {:ok, %AuthorizationCode{}}

  defp grant(_params),
    do: {:error, :unsupported_grant_type}

  defp send_token_response(conn, status, params) do
    conn
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("pragma", "no-cache")
    |> send_response(status, "application/json", params)
  end
end
