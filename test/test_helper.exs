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

defmodule DreddTest.Server do
  alias Dredd.OAuth.Grant.AuthorizationCode

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
  def authorize(%AuthorizationCode{}, _client), do: {:ok, "good_auth_code"}
  def authorize(_grant, _client), do: {:error, :invalid_response_type}

  @impl Dredd.Server
  def token(%AuthorizationCode{code: "good_auth_code"}, _client), do: {:ok, test_token()}
  def token(%AuthorizationCode{}, _client), do: {:error, :access_denied}
  def token(_grant, _token), do: {:error, :invalid_grant}
end
