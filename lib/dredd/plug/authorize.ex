defmodule Dredd.Plug.Authorize do
  @moduledoc false

  use Plug.ErrorHandler
  use Plug.Router

  alias Dredd.OAuth.{Application, Client, Grant}
  alias Grant.AuthorizationCode
  alias Plug.{Conn, CSRFProtection}

  import Dredd.Plug.Utils

  import Plug.Conn,
    only: [delete_session: 2, fetch_query_params: 2, fetch_session: 2, put_session: 3]

  require Logger

  @authorize_template "#{List.to_string(:code.priv_dir(:dredd))}/templates/authorize.html.eex"
  @external_resource @authorize_template

  plug Plug.Parsers,
    parsers: [:urlencoded],
    pass: ["application/x-www-form-urlencoded", "text/html"]

  plug Dredd.Plug.Authorize.Session
  plug :fetch_session
  plug CSRFProtection
  plug :fetch_query_params

  plug :match
  plug :dispatch

  get "/" do
    %Conn{query_params: params, private: %{server: server}} = conn

    with {:ok, client} <- validate_client(server, params),
         {:ok, auth_params} <- server.auth_params(client),
         {:ok, _grant} <- grant(client, params) do
      render_auth_page(conn, client, :ok, auth_params: auth_params)
    else
      {:error, reason} when reason in [:invalid_client_id, :invalid_redirect_uri] ->
        render_error(conn, reason)

      {:error, reason} ->
        error_redirect(conn, params, reason)
    end
  end

  post "/" do
    %Conn{private: %{server: server}, query_params: params} = conn
    user_id = Conn.get_session(conn, :user_id)

    with {:ok, client} <- validate_client(server, params),
         {:ok, _grant} <- grant(client, params),
         do: action(conn, server, client, not is_nil(user_id))
  end

  match "/", do: send_response(conn, :method_not_allowed, "text/plain", "")

  match _, do: send_response(conn, :not_found, "text/plain", "")

  defp action(
         %Conn{
           body_params:
             %{
               "action" => "login"
             } = params
         } = conn,
         server,
         client,
         false = _authenticated
       ) do
    with {:ok, auth_params} <- server.auth_params(client),
         auth_params =
           Enum.map(auth_params, fn {param, _value} ->
             {param, Map.get(params, Atom.to_string(param))}
           end),
         {:ok, user_id} <- server.authenticate(client, auth_params) do
      CSRFProtection.delete_csrf_token()

      conn
      |> put_session(:user_id, user_id)
      |> render_auth_page(client, :ok, auth_params: auth_params)
    else
      {:error, _reason} ->
        case server.auth_params(client) do
          {:ok, auth_params} ->
            render_auth_page(conn, client, :unauthorized, auth_params: auth_params, error: true)

          _ ->
            render_auth_page(conn, client, :unauthorized, error: true)
        end
    end
  end

  defp action(
         %Conn{
           query_params: %{"redirect_uri" => redirect_uri} = params,
           body_params: %{"action" => "allow"}
         } = conn,
         server,
         client,
         true = _authenticated
       ) do
    with {:ok, grant} <- grant(client, params),
         {:ok, redirect_params} <- Grant.authorize(grant, server, client, params) do
      redirect(conn, redirect_uri, redirect_params)
    else
      {:error, reason} ->
        error_redirect(conn, params, reason)
    end
  end

  defp action(
         %Conn{query_params: params, body_params: %{"action" => "deny"}} = conn,
         _server,
         _client,
         _authenticated
       ) do
    error_redirect(conn, params, :access_denied)
  end

  defp action(
         %Conn{body_params: %{"action" => "logout"}} = conn,
         server,
         client,
         true = _authenticated
       ) do
    case server.auth_params(client) do
      {:ok, auth_params} ->
        conn
        |> delete_session(:user_id)
        |> render_auth_page(client, :ok, auth_params: auth_params)

      {:error, _reason} ->
        render_auth_page(conn, client, :unauthorized, error: true)
    end
  end

  defp action(conn, _server, _client, _authenticated),
    do: render_error(conn, :access_denied)

  defp grant(_client, %{"response_type" => "code"}),
    do: {:ok, %AuthorizationCode{}}

  defp grant(_client, _params),
    do: {:error, :unsupported_response_type}

  defp handle_errors(%Conn{request_path: path, query_params: params} = conn, %{
         error: %CSRFProtection.InvalidCSRFTokenError{}
       }) do
    Logger.error(fn -> "Redirect on CSRF Token error" end)
    redirect(conn, path, params)
  end

  defp handle_errors(conn, error) do
    Logger.error(fn -> "Error handling request: #{inspect(error)}" end)
    send_response(conn, :internal_server_error, "text/plain", "")
  end

  defp render_auth_page(
         %Conn{
           host: host,
           request_path: path,
           private: %{server_name: server_name, static_dir: static_dir}
         } = conn,
         %Client{
           application: %Application{name: name, description: description, scopes: scopes}
         },
         status,
         assigns
       ) do
    user_id = Conn.get_session(conn, :user_id)

    send_response(
      conn,
      status,
      "text/html",
      EEx.eval_file(
        @authorize_template,
        assigns:
          [error: false]
          |> Keyword.merge(assigns)
          |> Keyword.merge(
            server_name: server_name,
            name: name,
            description: description,
            scopes: scopes,
            authenticated: not is_nil(user_id),
            csrf_token: CSRFProtection.get_csrf_token_for(host <> path),
            static_dir: static_dir
          )
      )
    )
  end

  defp error_redirect(conn, params, reason),
    do: redirect(conn, Map.fetch!(params, "redirect_uri"), %{"error" => reason})
end
