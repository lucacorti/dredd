defprotocol Dredd.OAuth.Grant do
  @moduledoc "Behaviour for OAuth grants"

  alias Dredd.{OAuth, Server}
  alias OAuth.{Client, Error, Token}

  @type t :: struct()
  @type attr :: atom()
  @type params :: %{required(String.t()) => String.t()}

  @typedoc "Authorization Code"
  @type auth_code :: String.t()

  @spec authorize(t(), Server.t(), Client.t(), params()) ::
          {:ok, params()}
          | {:error, Error.t()}
  def authorize(grant, server, client, params)

  @spec token(t(), Server.t(), Client.t(), params()) ::
          {:ok, Token.t()}
          | {:error, Error.t()}
  def token(grant, server, client, params)
end
