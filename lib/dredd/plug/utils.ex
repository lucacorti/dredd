defmodule Dredd.Plug.Utils do
  @moduledoc """
  Utilities for Dredd Plug
  """

  alias Dredd.{OAuth, Server}
  alias OAuth.{Client, Error}
  alias Plug.Conn
  alias Plug.Conn.Query

  import Plug.Conn
  import Plug.Conn.Utils

  require Logger

  @type content_type :: String.t()

  @error_template "#{List.to_string(:code.priv_dir(:dredd))}/templates/error.html.eex"
  @external_resource @error_template

  @spec validate_client(Server.t(), Conn.params()) ::
          {:ok, Client.t()}
          | {:error, :invalid_client_id | :invalid_redirect_uri | :invalid_scope}
  def validate_client(server, params) do
    scope = Map.get(params, "scope", "")
    client_id = Map.get(params, "client_id")
    redirect_uri = Map.get(params, "redirect_uri")

    with {:ok, client} <- server.client(client_id),
         :ok <- Client.validate_client_id(client, client_id),
         :ok <- Client.validate_redirect_uri(client, redirect_uri),
         :ok <- Client.validate_scope(client, scope) do
      {:ok, client}
    end
  end

  @spec fetch_param(Conn.params(), String.t(), Error.t()) ::
          {:ok, String.t()} | {:error, :invalid_request}
  def fetch_param(params, param, reason \\ :invalid_request) do
    case Map.fetch(params, param) do
      {:ok, value} ->
        {:ok, value}

      :error ->
        {:error, reason}
    end
  end

  @spec redirect(Conn.t(), String.t(), Conn.query_params()) :: Conn.t()
  def redirect(conn, redirect_uri, query_params) do
    location =
      redirect_uri
      |> URI.parse()
      |> struct(query: Query.encode(query_params), fragment: "_")
      |> URI.to_string()

    conn
    |> put_resp_header("location", location)
    |> send_resp(:see_other, "")
    |> halt()
  end

  @spec render_error(Conn.t(), Error.t()) :: Conn.t()
  def render_error(conn, code) do
    send_response(
      conn,
      :bad_request,
      "text/html",
      EEx.eval_file(@error_template, assigns: [code: code])
    )
  end

  @spec send_response(Conn.t(), Conn.status(), content_type(), any()) :: Conn.t()
  def send_response(conn, status, content_type, data) do
    with {:ok, _type, _subtype, _params} <- content_type(content_type),
         {:ok, data} <-
           encode(content_type, data) do
      conn
      |> put_resp_content_type(content_type)
      |> send_resp(status, data)
      |> halt()
    else
      error ->
        Logger.error(fn -> "Sending error response because: #{inspect(error)}" end)

        conn
        |> put_resp_content_type("text/plain")
        |> send_resp(500, "")
        |> halt()
    end
  end

  defp encode("application/json", data), do: Jason.encode(data)
  defp encode("text/" <> _format, text), do: {:ok, text}
  defp encode(_content_type, _data), do: {:error, :unknown_content_type}
end
