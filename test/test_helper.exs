ExUnit.start()

defmodule DreddTest.Helper do
  alias Ankh.HTTP.{Request, Response}
  alias Dredd.OAuth.{Application, Client, Token}

  def parse_cookies(response) do
    response
    |> Response.fetch_header_values("set-cookie")
    |> Enum.reduce([], fn set_cookie, cookies ->
      cookie =
        set_cookie
        |> String.split(";")
        |> List.first()

      [cookie | cookies]
    end)
    |> Enum.reverse()
    |> Enum.join(";")
  end

  def request(
        uri,
        method,
        path,
        query \\ %{},
        headers \\ [],
        body \\ nil,
        options \\ [follow_redirects: false]
      ) do
    request =
      uri
      |> Request.from_uri()
      |> Request.set_path("/oauth" <> path)
      |> Request.set_method(method)
      |> Request.set_query(query)
      |> Request.put_headers(headers)
      |> Request.set_body(body)
      |> Request.put_options(options)

    with {:ok, conn} <- Saigon.connect(uri),
         {:ok, _conn, response} <- Saigon.request(conn, request) do
      {:ok, Response.fetch_body(response)}
    else
      {:error, _conn, reason} ->
        {:error, reason}
    end
  end

  def test_client,
    do: %Client{
      id: "client_id",
      application: %Application{
        name: "test app",
        description: "Test application",
        redirect_uris: [
          "https://mytest/app"
        ]
      }
    }

  def test_token,
    do: %Token{
      access_token: "test_access_token",
      refresh_token: "test_refresh_token",
      expires_in: 86_400
    }
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
  alias DreddTest.AuthCode

  import DreddTest.Helper

  use Dredd.Server

  @impl Dredd.Server
  def authenticate(_client, _username, _password), do: {:ok, "1"}

  @impl Dredd.Server
  def secret_key_base,
    do:
      "NDzalAGwg3Phz8XYolvtHb5NIOI8KLmVfuWWjf0XQUzCgEN63CKYZSRFIr55gC9ppEBdtE7M06iVsF21mb2iPnyvTI4Ie7xYJUpX"

  @impl Dredd.Server
  def encryption_salt,
    do:
      "fI202rNW5dFQp1IK7eOYchEcq88jGDiXA391tjXzXRWO90Oi8fP5vFOIqo4WTuz8WvM3i0tLtyN08KrigoSn3PAtT7RWkdWtdyM0"

  @impl Dredd.Server
  def signing_salt,
    do:
      "NuaVhXMQ9zT2dGri9cMdEJSdn4DIO1rDHEBIcPHACCYTGSGioAOEkcAfXs8TynrWsqHLbCwPTg6gHg5d12xuwhVc3Ugc538B5zdg"

  @impl Dredd.Server
  def client("client_id"), do: {:ok, test_client()}
  def client(_client_id), do: {:error, :invalid_client_id}

  @impl Dredd.Server
  def grant(auth_code, code_verifier, redirect_uri) do
    with :ok <-
           AuthCode.validate(test_client(), auth_code, code_verifier, redirect_uri),
         do: {:ok, test_client(), test_token()}
  end

  @impl Dredd.Server
  def authorize(client, challenge, method, redirect_uri),
    do: AuthCode.generate(client, challenge, method, redirect_uri)
end
