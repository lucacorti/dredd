defmodule Dredd.Server do
  @moduledoc """
  OAuth Server implementation
  """

  alias Dredd.OAuth.{Application, Client, Grant, Token}

  @type t :: module()
  @type path :: String.t() | nil
  @type username :: String.t()
  @type password :: String.t()
  @type user_id :: String.t()

  @callback authenticate(Client.t(), username(), password()) :: {:ok, user_id()} | {:error, any()}

  @callback authorize(
              Client.t(),
              Grant.code_challenge(),
              Grant.challenge_method(),
              Application.redirect_uri()
            ) :: {:ok, Grant.auth_code()} | {:error, :unauthorized_client | :invalid_scope}

  @callback grant(
              Grant.auth_code(),
              Grant.code_verifier(),
              Application.redirect_uri()
            ) ::
              {:ok, Client.t(), Token.t()}
              | {:error,
                 :invalid_grant
                 | :invalid_scope
                 | :unauthorized_client}

  @callback client(Client.id()) :: {:ok, Client.t()} | {:error, :invalid_client_id}
  @callback template(Application.t()) :: path()
  @callback secret_key_base :: String.t()
  @callback encryption_salt :: String.t()
  @callback signing_salt :: String.t()

  @type prefix :: String.t()
  @type options :: [prefix: prefix()]

  defmodule Options do
    @moduledoc false

    import Plug.Conn, only: [put_private: 3]

    def init(opts), do: opts

    def call(conn, opts) do
      server = Keyword.fetch!(opts, :server)

      conn
      |> put_private(:server, server)
    end
  end

  @spec __using__(options()) :: any()
  defmacro __using__(args) do
    case Keyword.pop(args, :prefix, "/oauth") do
      {"/" <> _ = prefix, options} ->
        quote do
          @behaviour Dredd.Server

          @impl Dredd.Server
          def template(application), do: nil

          defoverridable Dredd.Server

          use Plug.Router

          plug Dredd.Server.Options, Keyword.put(unquote(options), :server, __MODULE__)

          plug :match
          plug :dispatch

          forward unquote(prefix), to: Dredd.Plug.Router
        end

      {prefix, _options} ->
        raise "Invalid :prefix '#{inspect(prefix)}': must be a string beginning with '/'"
    end
  end
end
