defmodule Dredd.Plug.Authorize.Session do
  @moduledoc false

  alias Plug.{Conn, Session}
  alias Session.COOKIE

  def init(opts), do: opts

  def call(
        %Conn{host: host, request_path: path, private: %{server: server, cookie: cookie}} = conn,
        opts
      ) do
    key =
      server
      |> Module.split()
      |> Enum.map(&String.downcase/1)
      |> Enum.join("_")

    options =
      opts
      |> Keyword.merge(cookie)
      |> Keyword.merge(
        store: COOKIE,
        key: "_#{key}_session",
        http_only: true,
        domain: host,
        path: path,
        secure: true
      )
      |> Session.init()

    Session.call(conn, options)
  end
end
