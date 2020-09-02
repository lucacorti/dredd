defmodule Dredd do
  @moduledoc """
  Opinionated Elixir OAuth Server Framework

  Dredd provides all the OAuth machinery needed to perform client authentication and delegates
  all the authorization decisions to your application, without imposing a specific data model.

  Dredd implements only a subset of OAuth 2.0. This is a deliberate decision to only support the
  safe and modern parts of the specification used in server-side, single page and native apps.

  Supported features:

    - Support for `OAuth 2.0` only.
    - Authorization endpoint supporting the `authorization_code` flow with mandatory `PKCE` and
      self-encoded `JWS` authorization codes.
    - Token endpoint supporting `code`, `client_credentials` and `refresh_token` grants with
      self-encoded `JWS` short-lived `access_token` and long-lived `refresh_token`.

  """
end
