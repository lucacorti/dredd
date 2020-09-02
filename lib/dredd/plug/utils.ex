defmodule Dredd.Plug.Utils do
  @moduledoc """
  Utilities for Dredd Plug
  """

  alias Dredd.OAuth.Error
  alias Plug.Conn
  alias Plug.Conn.Query

  import Plug.Conn
  import Plug.Conn.Utils

  require Logger

  @type content_type :: String.t()

  @error_template "priv/templates/error.html.eex"
  @external_resource @error_template

  @spec fetch_param(Conn.params(), String.t()) :: {:ok, String.t()} | {:error, :invalid_request}
  def fetch_param(params, param) do
    case Map.fetch(params, param) do
      {:ok, value} ->
        {:ok, value}

      :error ->
        {:error, :invalid_request}
    end
  end

  @spec get_param(Conn.params(), String.t(), any()) :: any()
  def get_param(params, param, default \\ nil), do: Map.get(params, param, default)

  @spec redirect(Conn.t(), String.t(), Conn.query_params()) :: Conn.t()
  def redirect(conn, redirect_uri, query_params) do
    location =
      redirect_uri
      |> URI.parse()
      |> struct(query: Query.encode(query_params))
      |> URI.to_string()

    conn
    |> put_resp_header("location", location)
    |> send_resp(:found, "")
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
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("pragma", "no-cache")
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
