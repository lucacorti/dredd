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

  defmodule AuthorizeSession do
    @moduledoc false

    alias Plug.Session
    alias Session.COOKIE

    def init(opts), do: opts

    def call(
          %Conn{host: host, request_path: path, private: %{server: server, cookie: cookie}} =
            conn,
          opts
        ) do
      key =
        server
        |> Module.split()
        |> Enum.map(&String.downcase/1)
        |> Enum.join("_")

      options =
        opts
        |> Keyword.merge(cookie)
        |> Keyword.merge(
          store: COOKIE,
          key: "_#{key}_session",
          http_only: true,
          domain: host,
          path: path,
          secure: true
        )
        |> Session.init()

      Session.call(conn, options)
    end
  end

  plug Plug.Parsers,
    parsers: [:urlencoded],
    pass: ["application/x-www-form-urlencoded", "text/html"]

  plug AuthorizeSession
  plug :fetch_session
  plug CSRFProtection
  plug :fetch_query_params

  plug :match
  plug :dispatch

  get "/" do
    %Conn{query_params: params, private: %{server: server}} = conn

    with {:ok, client, _redirect_uri} <- validate_client(server, params),
         {:ok, _grant} <- grant(client, params) do
      render_auth_page(conn, client, :ok)
    else
      {:error, reason} ->
        render_error(conn, reason)

      {:error, reason, _client, redirect_uri} ->
        redirect(conn, redirect_uri, %{"error_code" => reason})
    end
  end

  post "/" do
    %Conn{private: %{server: server}, query_params: params} = conn
    user_id = Conn.get_session(conn, :user_id)

    with {:ok, client, redirect_uri} <- validate_client(server, params),
         {:ok, _grant} <- grant(client, params),
         do: action(conn, server, client, redirect_uri, not is_nil(user_id))
  end

  match "/", do: send_response(conn, :method_not_allowed, "text/plain", "")

  match _, do: send_response(conn, :not_found, "text/plain", "")

  defp validate_client(server, params) do
    with {:ok, client_id} <- fetch_param(params, "client_id"),
         {:ok, client} <- server.client(client_id),
         :ok <- Client.validate_client_id(client, client_id),
         {:ok, redirect_uri} <- fetch_param(params, "redirect_uri"),
         :ok <- Client.validate_redirect_uri(client, redirect_uri) do
      {:ok, client, redirect_uri}
    end
  end

  defp action(
         %Conn{
           body_params: %{
             "action" => "login",
             "username" => username,
             "password" => password
           }
         } = conn,
         server,
         client,
         _redirect_uri,
         false = _authenticated
       ) do
    case server.authenticate(client, username, password) do
      {:ok, user_id} ->
        CSRFProtection.delete_csrf_token()

        conn
        |> put_session(:user_id, user_id)
        |> render_auth_page(client, :ok)

      {:error, _reason} ->
        render_auth_page(conn, client, :unauthorized, error: true)
    end
  end

  defp action(
         %Conn{query_params: params, body_params: %{"action" => "allow"}} = conn,
         server,
         client,
         redirect_uri,
         true = _authenticated
       ) do
    with {:ok, grant} <- grant(client, params),
         {:ok, redirect_params} <- Grant.authorize(grant, server, client, params) do
      redirect(conn, redirect_uri, redirect_params)
    else
      {:error, reason} ->
        render_error(conn, reason)

      {:error, reason, _client, redirect_uri} ->
        redirect(conn, redirect_uri, %{"error_code" => reason})
    end
  end

  defp action(
         %Conn{body_params: %{"action" => "deny"}} = conn,
         _server,
         _client,
         redirect_uri,
         _authenticated
       ) do
    redirect(conn, redirect_uri, %{"error_code" => :access_denied})
  end

  defp action(
         %Conn{body_params: %{"action" => "logout"}} = conn,
         _server,
         client,
         _redirect_uri,
         true = _authenticated
       ) do
    conn
    |> delete_session(:user_id)
    |> render_auth_page(client, :ok)
  end

  defp action(conn, _server, _client, _redirect_uri, _authenticated),
    do: render_error(conn, :access_denied)

  defp handle_errors(%Conn{request_path: path, query_params: params} = conn, %{
         reason: %CSRFProtection.InvalidCSRFTokenError{}
       }) do
    conn = fetch_query_params(conn, [])

    redirect(conn, path, params)
  end

  defp handle_errors(conn, error) do
    Logger.error(fn -> "Error handling request: #{inspect(error)}" end)
    send_response(conn, :internal_server_error, "text/plain", "")
  end

  defp grant(_client, %{"response_type" => "code"}),
    do: {:ok, %AuthorizationCode{}}

  defp grant(client, params),
    do: {:error, :unsupported_response_type, client, Map.get(params, "redirect_uri")}

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
         assigns \\ []
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
end
