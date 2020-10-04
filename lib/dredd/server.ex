defmodule Dredd.Server do
  @moduledoc """
  OAuth Server implementation
  """

  alias Dredd.OAuth.{Client, Grant, Token}

  @type t :: module()
  @type path :: String.t() | nil
  @type auth_param_opts :: [default: String.t(), placeholder: String.t(), required: boolean()]
  @type auth_params :: [{atom(), [{atom(), auth_param_opts()}]}]
  @type user_id :: String.t()
  @type authorize_error :: :unsupported_response_type | :unauthorized_client | :invalid_scope
  @type prepare_error :: :invalid_grant | :invalid_scope | :unauthorized_client
  @type token_error :: :invalid_grant | :invalid_scope | :unauthorized_client

  @callback auth_params(Client.t()) :: {:ok, auth_params()} | {:error, authorize_error()}
  @callback authenticate(Client.t(), auth_params()) ::
              {:ok, user_id()} | {:error, :access_denied}
  @callback authorize(Grant.t(), Client.t()) ::
              {:ok, Grant.auth_code()} | {:error, authorize_error()}
  @callback prepare(Grant.t(), Client.t()) :: {:ok, Grant.t()} | {:error, prepare_error()}
  @callback token(Grant.t(), Client.t()) :: {:ok, Token.t()} | {:error, token_error()}
  @callback client(Client.id()) :: {:ok, Client.t()} | {:error, :invalid_client_id}

  @type options :: [prefix: String.t(), cookie: keyword(), ssl: keyword()]

  @spec __using__(options()) :: any()
  defmacro __using__(args) do
    with {:otp_app, otp_app} when is_atom(otp_app) <-
           get_option(args, :otp_app, "You must pass the name of your OTP application", :dredd),
         {:name, server_name} when is_binary(server_name) <-
           get_option(args, :name, "You must pass the name of your authorization server"),
         {:prefix, "/" <> _ = prefix} when is_binary(prefix) <-
           get_option(
             args,
             :prefix,
             "you must provide a prefix for OAuth2 endpoints (e.g. '/oauth')",
             "/oauth"
           ),
         {:cookie, cookie} when is_list(cookie) <-
           get_option(
             args,
             :cookie,
             "see https://hexdocs.pm/plug/Plug.Session.COOKIE.html#module-options"
           ),
         {:ssl, ssl} when is_list(ssl) <-
           get_option(args, :ssl, "see https://hexdocs.pm/plug/Plug.SSL.html#content") do
      quote do
        @behaviour Dredd.Server

        use Plug.Router

        plug Plug.SSL, unquote(ssl)
        plug Plug.Static, at: "#{unquote(prefix)}/static", from: unquote(otp_app)
        plug :match
        plug :dispatch

        forward unquote(prefix),
          to: Dredd.Plug.Router,
          private: %{
            server_name: unquote(server_name),
            server: __MODULE__,
            static_dir: "#{unquote(prefix)}/static",
            cookie: unquote(cookie),
            ssl: unquote(ssl)
          }
      end
    else
      {:error, option, msg} ->
        raise "Missing option #{option}: #{msg}"

      {option, value} ->
        raise "Invalid value for option #{option}: '#{inspect(value)}'"
    end
  end

  defp get_option(args, option, error_msg, default \\ nil)

  defp get_option(args, option, error_msg, nil) do
    case Keyword.fetch(args, option) do
      :error ->
        {:error, option, error_msg}

      {:ok, value} ->
        {option, value}
    end
  end

  defp get_option(args, option, _error_msg, default) do
    case Keyword.fetch(args, option) do
      :error ->
        {option, default}

      {:ok, value} ->
        {option, value}
    end
  end
end
