defmodule Dredd.OAuth.Grant.AuthorizationCode do
  @moduledoc """
  OAuth Authorization Code Grant
  """
  alias Dredd.OAuth.{Client, Grant}

  import Dredd.Plug.Utils

  @behaviour Grant

  @impl Grant
  def authorize(server, client, query) do
    scopes = get_scopes(query)

    with {:ok, challenge} <- fetch_param(query, "code_challenge"),
         {:ok, method} <- fetch_param(query, "code_challenge_method"),
         {:ok, state} <- fetch_param(query, "state"),
         {:ok, redirect_uri} <- fetch_param(query, "redirect_uri"),
         :ok <- Client.validate_scopes(client, scopes),
         {:ok, auth_code} <- server.authorize(client, challenge, method, redirect_uri) do
      {:ok, %{"auth_code" => auth_code, "state" => state}}
    else
      {:error, reason} ->
        {:error, reason, client, get_param(query, "redirect_uri")}
    end
  end

  defp get_scopes(params) do
    params
    |> get_param("scope", "")
    |> String.trim()
    |> String.split(" ")
    |> Enum.reject(fn
      "" -> true
      _scope -> false
    end)
  end

  @impl Grant
  def token(server, query) do
    with {:ok, code} <- fetch_param(query, "code"),
         {:ok, code_verifier} <- fetch_param(query, "code_verifier"),
         {:ok, redirect_uri} <- fetch_param(query, "redirect_uri"),
         {:ok, client, token} <- server.grant(code, code_verifier, redirect_uri),
         :ok <- Client.validate_redirect_uri(client, redirect_uri) do
      {:ok, token}
    end
  end
end
