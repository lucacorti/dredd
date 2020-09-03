defmodule Dredd.Plug.Token do
  @moduledoc false

  use Plug.ErrorHandler
  use Plug.Router

  alias Dredd.OAuth.Grant
  alias Grant.AuthorizationCode
  alias Plug.Conn

  import Dredd.Plug.Utils

  require Logger

  @error_template "priv/templates/error.html.eex"
  @external_resource @error_template

  plug Plug.Parsers,
    parsers: [:urlencoded]

  plug :match
  plug :dispatch

  post "/" do
    %Conn{private: %{server: server}, body_params: params} = conn

    with {:ok, grant} <- grant(params),
         {:ok, token} <- Grant.token(grant, server, params) do
      send_response(conn, :ok, "application/json", token)
    else
      {:error, reason} ->
        send_response(conn, :bad_request, "application/json", %{"error" => reason})
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
end
