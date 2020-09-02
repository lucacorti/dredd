defmodule Dredd.Plug.Router do
  @moduledoc false

  use Plug.ErrorHandler
  use Plug.Router

  alias Dredd.Plug.{Authorize, Token}

  import Dredd.Plug.Utils

  plug :match
  plug :dispatch

  forward "/authorize", to: Authorize
  forward "/token", to: Token

  match _, do: send_response(conn, :not_found, "text/plain", "")
end
