defmodule Dredd.OAuth.Grant.AuthorizationCode do
  @moduledoc """
  OAuth Authorization Code Grant
  """
  alias Dredd.OAuth.{Application, Client, Grant}

  import Dredd.Plug.Utils

  @typedoc "PKCE Code Challenge Method"
  @type code_challenge_method :: String.t()

  @typedoc "PKCE Code Challenge"
  @type code_challenge :: String.t()

  @typedoc "PKCE Code Verifier"
  @type code_verifier :: String.t()

  @typedoc "Client State"
  @type state :: String.t()

  @typedoc "Authorization Code Grant"
  @type t :: %__MODULE__{
          code: Grant.auth_code(),
          state: state(),
          code_challenge: code_challenge(),
          code_challenge_method: code_challenge_method(),
          code_verifier: code_verifier(),
          scopes: Application.scopes(),
          redirect_uri: Application.redirect_uri()
        }
  defstruct code: nil,
            code_challenge: nil,
            code_challenge_method: nil,
            code_verifier: nil,
            redirect_uri: nil,
            scopes: [],
            state: nil

  defimpl Grant do
    alias Dredd.OAuth.{Client, Grant}
    alias Dredd.OAuth.Grant.AuthorizationCode

    def authorize(authorization_code, server, client, params) do
      scopes = get_scopes(params)

      with {:ok, code_challenge} <- fetch_param(params, "code_challenge"),
           {:ok, code_challenge_method} <- fetch_param(params, "code_challenge_method"),
           {:ok, state} <- fetch_param(params, "state"),
           {:ok, redirect_uri} <- fetch_param(params, "redirect_uri"),
           :ok <- Client.validate_scopes(client, scopes),
           {:ok, %AuthorizationCode{code: code}} <-
             server.authorize(
               %{
                 authorization_code
                 | code_challenge: code_challenge,
                   code_challenge_method: code_challenge_method,
                   redirect_uri: redirect_uri,
                   state: state,
                   scopes: scopes
               },
               client
             ) do
        {:ok, %{"code" => code, "state" => state}}
      else
        {:error, reason} ->
          {:error, reason, client, Map.get(params, "redirect_uri")}
      end
    end

    def token(authorization_code, server, client, params) do
      with {:ok, code} <- fetch_param(params, "code"),
           {:ok, redirect_uri} <- fetch_param(params, "redirect_uri"),
           {:ok, code_verifier} <- fetch_param(params, "code_verifier") do
        server.token(
          %{
            authorization_code
            | code: code,
              code_verifier: code_verifier,
              redirect_uri: redirect_uri
          },
          client
        )
      end
    end

    defp get_scopes(params) do
      params
      |> Map.get("scope", "")
      |> String.split(" ", trim: true)
    end
  end
end
