defmodule Dredd.OAuth.Application do
  @moduledoc """
  OAuth Application
  """

  @type redirect_uri :: String.t()
  @type scope :: String.t()
  @type scopes :: [scope()]

  @type t :: %__MODULE__{
          name: String.t(),
          description: String.t(),
          redirect_uris: [redirect_uri()],
          scopes: scopes()
        }
  @enforce_keys [:name, :description]
  defstruct name: nil, description: nil, redirect_uris: [], scopes: []
end
