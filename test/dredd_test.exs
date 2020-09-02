defmodule DreddTest do
  use ExUnit.Case
  doctest Dredd

  alias Ankh.HTTP.Response
  alias DreddTest.{AuthCode, Server}
  alias Plug.Conn.{Query, Utils}

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
    port = 8_000

    with {:ok, pid} <- Plug.Cowboy.http(Server, [], port: port) do
      %{
        uri: URI.parse("http://localhost:#{port}"),
        server: pid,
        auth_code_authorize_params: @auth_code_authorize_params,
        auth_code_token_params: @auth_code_token_params
      }
    end
  end

  describe "generic" do
    test "server starts", %{server: server} do
      assert is_pid(server)
    end

    test "404 on missing url", %{uri: uri} do
      assert {:ok, %Response{status: 404}} = request(uri, :GET, "/missing-path")
    end

    test "authorize: 405 on invalid method", %{uri: uri} do
      assert {:ok, %Response{status: 405}} = request(uri, :HEAD, "/authorize")
    end

    test "authorize: 400 on missing query parameters", %{uri: uri} do
      assert {:ok, %Response{status: 400}} = request(uri, :GET, "/authorize")
    end

    test "authorize: 400 on invalid response_type", %{uri: uri} do
      assert {:ok, %Response{status: 400}} =
               request(uri, :GET, "/authorize", %{response_type: "bad_response_type"})
    end

    test "token: 405 on invalid method", %{uri: uri} do
      assert {:ok, %Response{status: 405}} = request(uri, :GET, "/token")
    end

    test "token: 400 on missing query parameters", %{uri: uri} do
      assert {:ok, %Response{status: 400}} = request(uri, :POST, "/token")
    end

    test "token: 400 on invalid grant_type", %{uri: uri} do
      assert {:ok, %Response{status: 400}} =
               request(uri, :POST, "/token", %{grant_type: "bad_grant_type"})
    end
  end

  describe "authorization_code authorize" do
    test "error on one required parameter missing", %{
      uri: uri,
      auth_code_authorize_params: auth_code_authorize_params
    } do
      for param <- auth_code_authorize_params do
        param_name =
          param
          |> Tuple.to_list()
          |> List.first()

        assert {_param, params} = Keyword.pop(auth_code_authorize_params, param_name)

        assert {:ok, %Response{status: status}} = request(uri, :GET, "/authorize", params)

        expected_status = case param_name do
          param_name when param_name in [:client_id, :redirect_uri] -> 400
          _param_name -> 302
        end
        assert status == expected_status,
               "Status: #{status} Removed: #{param_name} Request params: #{inspect(params)}"
      end
    end

    test "400 on only one parameter provided", %{
      uri: uri,
      auth_code_authorize_params: auth_code_authorize_params
    } do
      for param <- auth_code_authorize_params do
        param_name =
          param
          |> Tuple.to_list()
          |> List.first()

        {param, _params} = Keyword.pop(auth_code_authorize_params, param_name)

        assert {:ok, %Response{status: 400}} =
                 request(uri, :GET, "/authorize", [{param_name, param}]),
               "Only parameter provided in request: #{inspect(param_name)}"
      end
    end

    test "400 on bad client id", %{
      uri: uri,
      auth_code_authorize_params: auth_code_authorize_params
    } do
      params = Keyword.replace!(auth_code_authorize_params, :client_id, "bad_client_id")
      assert {:ok, %Response{status: 400}} = request(uri, :GET, "/authorize", params)
    end

    test "200 on correct request", %{
      uri: uri,
      auth_code_authorize_params: auth_code_authorize_params
    } do
      assert {:ok, %Response{status: 200} = response} =
               request(uri, :GET, "/authorize", auth_code_authorize_params)
    end
  end

  describe "authorization_code token" do
    test "200 on correct request", %{
      uri: uri,
      auth_code_token_params: auth_code_token_params
    } do
      data =
        auth_code_token_params
        |> Enum.into(%{})
        |> Query.encode()

      assert {:ok, %Response{status: 200} = response} =
               request(
                 uri,
                 :POST,
                 "/token",
                 %{},
                 [{"content-type", "application/x-www-form-urlencoded"}],
                 data
               )

      assert [{:ok, "application", "json", _}] =
               response
               |> Response.fetch_header_values("content-type")
               |> Enum.map(&Utils.content_type(&1))
    end
  end
end
