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

  @typedoc "Authorization Code Grant"
  @type t :: %__MODULE__{
          client_id: Client.id(),
          code: Grant.auth_code(),
          code_challenge: code_challenge(),
          code_challenge_method: code_challenge_method(),
          scope: Application.scope(),
          redirect_uri: Application.redirect_uri()
        }
  defstruct client_id: nil,
            code: nil,
            code_challenge: nil,
            code_challenge_method: nil,
            redirect_uri: nil,
            scope: nil

  defimpl Grant do
    alias Dredd.OAuth.Grant.AuthorizationCode

    def authorize(authorization_code, server, client, params) do
      with {:ok, %AuthorizationCode{code: code}} <-
             server.authorize(
               %{
                 authorization_code
                 | client_id: Map.get(params, "client_id"),
                   code_challenge: Map.get(params, "code_challenge"),
                   code_challenge_method: Map.get(params, "code_challenge_method"),
                   redirect_uri: Map.get(params, "redirect_uri"),
                   scope: Map.get(params, "scope")
               },
               client
             ) do
        case Map.get(params, "state") do
          nil ->
            {:ok, %{"code" => code}}

          state ->
            {:ok, %{"code" => code, "state" => state}}
        end
      end
    end

    def token(authorization_code, server, client, params) do
      with {:ok, code} <- fetch_param(params, "code"),
           {:ok, authorization_code} <-
             server.prepare(%{authorization_code | code: code}, client),
           {:ok, authorization_code} <- check_params(authorization_code, params) do
        server.token(authorization_code, client)
      end
    end

    defp check_params(authorization_code, params) do
      client_id = Map.get(params, "client_id")
      code_verifier = Map.get(params, "code_verifier")
      redirect_uri = Map.get(params, "redirect_uri")

      with {:ok, authorization_code} <- check_client_id(authorization_code, client_id),
           {:ok, authorization_code} <- check_redirect_uri(authorization_code, redirect_uri),
           {:ok, authorization_code} <- check_pkce_challenge(authorization_code, code_verifier) do
        {:ok, authorization_code}
      end
    end

    defp check_client_id(
           %AuthorizationCode{client_id: client_id} = authorization_code,
           client_id
         ),
         do: {:ok, authorization_code}

    defp check_client_id(_authorization_code, _client_id), do: {:error, :invalid_client_id}

    defp check_redirect_uri(
           %AuthorizationCode{redirect_uri: redirect_uri} = authorization_code,
           redirect_uri
         ),
         do: {:ok, authorization_code}

    defp check_redirect_uri(_authorization_code, _redirect_uri),
      do: {:error, :invalid_redirect_uri}

    defp check_pkce_challenge(
           %AuthorizationCode{
             code_challenge: nil,
             code_challenge_method: nil
           } = grant,
           nil
         ),
         do: {:ok, grant}

    defp check_pkce_challenge(
           %AuthorizationCode{
             code_challenge: challenge,
             code_challenge_method: "S256"
           } = grant,
           verifier
         ) do
      :sha256
      |> :crypto.hash(verifier)
      |> Base.encode64(padding: false)
      |> case do
        ^challenge -> {:ok, grant}
        _ -> {:error, :invalid_grant}
      end
    end

    defp check_pkce_challenge(_authorization_code, _verifier), do: {:error, :invalid_grant}
  end
end
