defmodule DreddTest do
  use ExUnit.Case, async: true
  use Plug.Test
  doctest Dredd

  alias DreddTest.{AuthCode, Server}
  alias Plug.Conn
  alias Conn.{Query, Utils}

  import DreddTest.Helper

  @test_client test_client()
  @redirect_uri "https://mytest/app"
  @code_verifier "well-formed-client-verifier-string-for-testing"
  @code_challenge_method "S256"
  @code_challenge AuthCode.generate_challenge(@code_verifier)
  @auth_code AuthCode.generate(
               test_client(),
               @code_challenge,
               @code_challenge_method,
               @redirect_uri
             )
  @auth_code_authorize_params [
    response_type: "code",
    client_id: @test_client.id,
    code_challenge: @code_challenge,
    code_challenge_method: @code_challenge_method,
    redirect_uri: @redirect_uri,
    state: "some_state"
  ]

  @auth_code_token_params [
    grant_type: "authorization_code",
    client_id: @test_client.id,
    redirect_uri: @redirect_uri,
    code_verifier: @code_verifier,
    code: @auth_code
  ]

  setup_all do
    %{
      auth_code_authorize_params: @auth_code_authorize_params,
      auth_code_token_params: @auth_code_token_params
    }
  end

  describe "generic" do
    test "404 on missing url" do
      assert %Conn{status: 404} = :get |> request("/missing-path")
    end

    test "authorize: 405 on invalid method" do
      assert %Conn{status: 405} = :head |> request("/authorize")
    end

    test "authorize: 400 on missing query parameters" do
      assert %Conn{status: 400} = :get |> request("/authorize")
    end

    test "authorize: 400 on invalid response_type" do
      assert %Conn{status: 400} =
               :get |> request("/authorize", %{response_type: "bad_response_type"})
    end

    test "token: 405 on invalid method" do
      assert %Conn{status: 405} = :get |> request("/token")
    end

    test "token: 400 on missing query parameters" do
      assert %Conn{status: 400} = :post |> request("/token")
    end

    test "token: 400 on invalid grant_type" do
      assert %Conn{status: 400} = :post |> request("/token", %{grant_type: "bad_grant_type"})
    end
  end

  describe "authorization_code authorize" do
    test "error on one required parameter missing", %{
      auth_code_authorize_params: auth_code_authorize_params
    } do
      for param <- auth_code_authorize_params do
        param_name =
          param
          |> Tuple.to_list()
          |> List.first()

        assert {_param, params} = Keyword.pop(auth_code_authorize_params, param_name)

        assert conn = :get |> request("/authorize", params)

        case param_name do
          param_name when param_name in [:client_id, :redirect_uri] ->
            assert %Conn{status: 400} = conn

          param_name when param_name in [:response_type] ->
            assert %Conn{status: 302} = conn

            %{"error_code" => _value} =
              conn
              |> get_resp_header("location")
              |> List.first()
              |> URI.parse()
              |> Map.fetch!(:query)
              |> Query.decode()

          _param_name ->
            assert %Conn{status: 200} = conn

            assert [{:ok, "text", "html", _}] =
                     conn
                     |> get_resp_header("content-type")
                     |> Enum.map(&Utils.content_type(&1))
        end
      end
    end

    test "400 on only one parameter provided", %{
      auth_code_authorize_params: auth_code_authorize_params
    } do
      for param <- auth_code_authorize_params do
        param_name =
          param
          |> Tuple.to_list()
          |> List.first()

        {param, _params} = Keyword.pop(auth_code_authorize_params, param_name)

        assert %Conn{status: 400} = :get |> request("/authorize", [{param_name, param}])
        "Only parameter provided in request: #{inspect(param_name)}"
      end
    end

    test "400 on bad client id", %{
      auth_code_authorize_params: auth_code_authorize_params
    } do
      params = Keyword.replace!(auth_code_authorize_params, :client_id, "bad_client_id")
      assert %Conn{status: 400} = :get |> request("/authorize", params)
    end

    test "200 on correct request", %{
      auth_code_authorize_params: auth_code_authorize_params
    } do
      assert %Conn{status: 200} = :get |> request("/authorize", auth_code_authorize_params)
    end
  end

  describe "authorization_code token" do
    test "200 on correct request", %{
      auth_code_token_params: auth_code_token_params
    } do
      data =
        auth_code_token_params
        |> Enum.into(%{})
        |> Query.encode()

      assert %Conn{status: 200} =
               conn =
               :post
               |> request("/token", data, [{"content-type", "application/x-www-form-urlencoded"}])

      assert [{:ok, "application", "json", _}] =
               conn
               |> get_resp_header("content-type")
               |> Enum.map(&Utils.content_type(&1))
    end
  end

  def request(method, path, params \\ "", headers \\ []) do
    conn = conn(method, "https://www.example.com/oauth" <> path, params)

    headers
    |> Enum.reduce(conn, fn {key, value}, conn -> put_req_header(conn, key, value) end)
    |> Server.call([])
    |> fetch_query_params([])
  end
end
