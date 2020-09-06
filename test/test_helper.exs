ExUnit.start()

defmodule DreddTest.Helper do
  alias Dredd.OAuth.{Application, Client, Token}

  @alpha "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  @numeric "0123456789"
  @alphanumeric @alpha <> String.downcase(@alpha) <> @numeric

  def test_client,
    do: %Client{
      id: "client_id",
      application: %Application{
        name: "Test application",
        description: "A test application doing nothing really.",
        redirect_uris: [
          "https://mytest/app"
        ]
        # scopes: ["read", "write"]
      }
    }

  def test_token,
    do: %Token{
      access_token: "test_access_token",
      refresh_token: "test_refresh_token",
      expires_in: 86_400
    }

  def random_str(length) do
    @alphanumeric
    |> String.split("", trim: true)
    |> do_random_str(length)
  end

  defp do_random_str(lists, length) do
    length
    |> get_range()
    |> Enum.reduce([], fn _, acc -> [Enum.random(lists) | acc] end)
    |> Enum.join("")
  end

  defp get_range(length) when length > 1, do: 1..length
  defp get_range(_length), do: [1]
end

defmodule DreddTest.AccessToken do
  alias Joken.{Config, Signer}

  use Config

  @key "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAx1PPWN8kop0mhViuH+Q41wrfbrhUhCNST/3l3fK/ZfoAoGCCqGSM49
AwEHoUQDQgAEiQmMfEH65ZWpSB2k+yR6DnnzjVDel24Hf6/hi4hX5BH0M+3WmaHx
Pv//2GOE8xkVsLAYXHUbgc9YdCiI6wBvLg==
-----END EC PRIVATE KEY-----"

  @impl Config
  def token_config do
    [aud: "access_token", iss: "oauth", default_exp: access_token_expires_in()]
    |> default_claims()
  end

  def grant(token) do
    with {:ok, access_token, _claims} <- generate_and_sign(%{}, signer()),
         {:ok, refresh_token, _claims} <- generate_and_sign(%{}, signer()) do
      {:ok, %{token | access_token: access_token, refresh_token: refresh_token}}
    end
  end

  defp access_token_expires_in, do: 3600

  defp signer, do: Signer.create("ES256", %{"pem" => @key})
end

defmodule DreddTest.AuthCode do
  @moduledoc """
  OAuth Authorization Code
  """
  alias Dredd.OAuth
  alias OAuth.{Application, Client}
  alias Joken.{Config, Signer}

  use Config

  @key "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAx1PPWN8kop0mhViuH+Q41wrfbrhUhCNST/3l3fK/ZfoAoGCCqGSM49
AwEHoUQDQgAEiQmMfEH65ZWpSB2k+yR6DnnzjVDel24Hf6/hi4hX5BH0M+3WmaHx
Pv//2GOE8xkVsLAYXHUbgc9YdCiI6wBvLg==
-----END EC PRIVATE KEY-----"

  @impl Config
  def token_config do
    [aud: "auth_code", iss: "dredd", default_exp: 60]
    |> default_claims()
  end

  @spec generate(
          Client.t(),
          Grant.code_challenge(),
          Grant.challenge_method(),
          Application.redirect_uri()
        ) ::
          {:ok, Grant.auth_code()} | {:error, atom()}
  def generate(%Client{id: client_id}, challenge, "S256" = method, redirect_uri) do
    with {:ok, token, _claims} <-
           generate_and_sign(
             %{
               "xci" => client_id,
               "xcm" => method,
               "xcs" => challenge,
               "xru" => redirect_uri
             },
             signer()
           ),
         do: token
  end

  def generate(_client, _challenge, _method, _redirect_uri),
    do: {:error, :invalid_challenge_method}

  def validate(%Client{id: client_id}, auth_code, verifier, redirect_uri) do
    with {:ok,
          %{"xci" => ^client_id, "xcm" => "S256", "xcs" => challenge, "xru" => ^redirect_uri}} <-
           verify_and_validate(auth_code, signer()),
         ^challenge <- generate_challenge(verifier) do
      :ok
    else
      _ ->
        {:error, :access_denied}
    end
  end

  def generate_challenge(verifier), do: :sha256 |> :crypto.hash(verifier) |> Base.encode64()

  defp signer, do: Signer.create("ES256", %{"pem" => @key})
end

defmodule DreddTest.Server do
  alias Dredd.OAuth.Grant.AuthorizationCode
  alias DreddTest.AuthCode

  import DreddTest.Helper

  use Dredd.Server,
    name: "Test Server",
    cookie: [
      secret_key_base: random_str(120),
      encryption_salt: random_str(120),
      signing_salt: random_str(120)
    ],
    ssl: []

  @impl Dredd.Server
  def authenticate(_client, "test_user", "test_password"), do: {:ok, "1"}
  def authenticate(_client, _username, _password), do: {:error, :access_denied}

  @impl Dredd.Server
  def client("client_id"), do: {:ok, test_client()}
  def client(_client_id), do: {:error, :invalid_client_id}

  @impl Dredd.Server
  def authorize(
        %AuthorizationCode{
          code_challenge: challenge,
          code_challenge_method: method,
          redirect_uri: redirect_uri
        },
        client
      ),
      do: {:ok, AuthCode.generate(client, challenge, method, redirect_uri)}

  def authorize(_grant, _client), do: {:error, :invalid_response_type}

  @impl Dredd.Server
  def token(
        %AuthorizationCode{code: code, code_verifier: verifier, redirect_uri: redirect_uri},
        client
      ) do
    with :ok <- AuthCode.validate(client, code, verifier, redirect_uri),
         do: {:ok, test_token()}
  end

  def token(_grant, _token), do: {:error, :invalid_grant}
end
