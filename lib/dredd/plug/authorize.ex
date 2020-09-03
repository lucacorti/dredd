defmodule Dredd.Plug.Authorize do
  @moduledoc false

  use Plug.ErrorHandler
  use Plug.Router

  alias Dredd.OAuth.{Application, Client, Grant}
  alias Grant.AuthorizationCode
  alias Plug.{Conn, CSRFProtection}

  import Dredd.Plug.Utils
  import Plug.Conn, only: [fetch_session: 2, put_session: 3]

  require Logger

  @authorize_template "priv/templates/authorize/success.html.eex"
  @external_resource @authorize_template

  defmodule Session do
    @moduledoc false

    alias Plug.Session
    alias Session.COOKIE

    def init(opts), do: opts

    def call(%Conn{private: %{server: server}} = conn, opts) do
      store_opts =
        Enum.map([:secret_key_base, :encryption_salt, :signing_salt], &get_option(server, &1))

      options =
        opts
        |> Keyword.merge(store_opts)
        |> Keyword.merge(store: COOKIE, key: "_session")
        |> Session.init()

      Session.call(conn, options)
    end

    defp get_option(server, option) do
      case apply(server, option, []) do
        value when not is_nil(value) ->
          {option, value}

        _ ->
          raise "#{__MODULE__}: Required option #{option} missing"
      end
    end
  end

  plug Plug.Parsers,
    parsers: [:urlencoded],
    pass: ["text/html"]

  plug Session
  plug :fetch_session
  plug CSRFProtection

  plug :match
  plug :dispatch

  get "/" do
    %Conn{private: %{server: server}, query_params: params} = conn
    user_id = Conn.get_session(conn, :user_id)

    with {:ok,
          %Client{
            application: %Application{name: name, description: description} = application
          } = client, _redirect_uri} <- validate_client(server, params),
         {:ok, _grant} <- grant(client, params) do
      send_response(
        conn,
        :ok,
        "text/html",
        EEx.eval_file(
          server.template(application) || @authorize_template,
          assigns: [
            name: name,
            description: description,
            scopes: [],
            user_id: user_id,
            csrf_token: CSRFProtection.get_csrf_token()
          ]
        )
      )
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
         do: action(conn, server, client, redirect_uri, user_id)
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
             "action" => "authenticate",
             "username" => username,
             "password" => password
           }
         } = conn,
         server,
         %Client{application: %Application{name: name, description: description} = application} =
           client,
         _redirect_uri,
         user_id
       )
       when is_nil(user_id) do
    with {:ok, user_id} <- server.authenticate(client, username, password) do
      CSRFProtection.delete_csrf_token()

      conn
      |> put_session(:user_id, user_id)
      |> send_response(
        :ok,
        "text/html",
        EEx.eval_file(
          server.template(application) || @authorize_template,
          assigns: [
            name: name,
            description: description,
            scopes: [],
            user_id: user_id,
            csrf_token: CSRFProtection.get_csrf_token()
          ]
        )
      )
    end
  end

  defp action(
         %Conn{query_params: params, body_params: %{"action" => "allow"}} = conn,
         server,
         client,
         redirect_uri,
         user_id
       )
       when not is_nil(user_id) do
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
         user_id
       )
       when not is_nil(user_id) do
    redirect(conn, redirect_uri, %{"error_code" => :access_denied})
  end

  defp action(conn, _server, _client, _redirect_uri, _user_id),
    do: render_error(conn, :access_denied)

  defp handle_errors(conn, error) do
    Logger.error(fn -> "Error handling request: #{inspect(error)}" end)
    send_response(conn, :internal_server_error, "text/plain", "")
  end

  defp grant(_client, %{"response_type" => "code"}),
    do: {:ok, %AuthorizationCode{}}

  defp grant(client, params),
    do: {:error, :unsupported_response_type, client, get_param(params, "redirect_uri")}
end
