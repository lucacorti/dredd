defmodule Dredd.OAuth.Error do
  @moduledoc """
  OAuth error
  """

  @type t ::
          :access_denied
          | :invalid_client_id
          | :invalid_grant
          | :invalid_redirect_uri
          | :invalid_request
          | :invalid_scope
          | :server_error
          | :temporarily_unavailable
          | :unauthorized_client
          | :unsupported_grant_type
          | :unsupported_response_type
end
