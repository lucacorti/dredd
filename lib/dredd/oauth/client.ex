defmodule Dredd.OAuth.Client do
  @moduledoc """
  OAuth Client
  """
  alias Dredd.OAuth.Application

  @type id :: String.t()
  @type secret :: String.t()

  @type t :: %__MODULE__{id: id(), secret: secret(), application: Application.t()}
  @enforce_keys [:id, :application]
  defstruct id: nil, secret: nil, application: nil

  @spec validate_client_id(t(), id()) :: :ok | {:error, :invalid_client_id}
  def validate_client_id(%__MODULE__{id: client_id}, client_id), do: :ok
  def validate_client_id(_client, _client_id), do: {:error, :invalid_client_id}

  @spec validate_redirect_uri(t(), Application.redirect_uri()) ::
          :ok | {:error, :invalid_redirect_uri}
  def validate_redirect_uri(
        %__MODULE__{application: %Application{redirect_uris: redirect_uris}},
        redirect_uri
      ) do
    Enum.reduce_while(redirect_uris, {:error, :invalid_redirect_uri}, fn
      ^redirect_uri, _acc -> {:halt, :ok}
      _uri, _acc -> {:cont, {:error, :invalid_redirect_uri}}
    end)
  end

  @spec validate_scope(t(), String.t()) :: :ok | {:error, :invalid_scope}
  def validate_scope(
        %__MODULE__{application: %Application{scopes: application_scopes}},
        scope
      ) do
    scope
    |> String.split(" ", trim: true)
    |> Enum.reduce_while(:ok, fn
      scope, _acc ->
        if scope in application_scopes do
          {:cont, :ok}
        else
          {:halt, {:error, :invalid_scope}}
        end
    end)
  end
end
