defmodule Dredd.OAuth.Grant do
  @moduledoc "Behaviour for OAuth grants"

  alias Dredd.OAuth.{Application, Client, Error, Token}
  alias Dredd.Server
  alias Plug.Conn

  @type t :: module()
  @type auth_code :: String.t()
  @type challenge_method :: String.t()
  @type code_challenge :: String.t()
  @type code_verifier :: String.t()
  @type params :: Conn.params()
  @type state :: String.t()

  @callback authorize(Server.t(), Client.t(), params()) ::
              {:ok, params()}
              | {:error, Error.t(), Client.t(), Application.redirect_uri()}
  @callback token(Server.t(), params()) ::
              {:ok, Application.t(), Token.t()}
              | {:error, Error.t()}
end
