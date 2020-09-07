defmodule Dredd.OAuth.Token do
  @moduledoc """
  OAuth Token
  """
  @type expire :: non_neg_integer()
  @type scope :: String.t()
  @type token :: String.t()
  @type type :: String.t()

  @type t :: %__MODULE__{
          access_token: token(),
          expires_in: expire(),
          refresh_token: token(),
          token_type: type()
        }
  @enforce_keys [:access_token, :expires_in, :refresh_token]
  @derive Jason.Encoder
  defstruct access_token: nil, expires_in: nil, refresh_token: nil, token_type: "Bearer"
end
