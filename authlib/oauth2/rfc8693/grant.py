"""authlib.oauth2.rfc8693.grant.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementation of the OAuth 2.0 Token Exchange grant type per `RFC 8693`_.

.. _`RFC 8693`: https://tools.ietf.org/html/rfc8693
"""

import logging

from ..rfc6749.errors import InvalidGrantError
from ..rfc6749.errors import InvalidRequestError
from ..rfc6749.errors import InvalidScopeError
from ..rfc6749.errors import UnauthorizedClientError
from ..rfc6749.grants import BaseGrant
from ..rfc6749.grants import TokenEndpointMixin
from ..rfc6749.hooks import hooked
from ..rfc6749.util import list_to_scope
from ..rfc6749.util import scope_to_list

log = logging.getLogger(__name__)

#: grant_type value for token exchange
GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"

#: token type identifier for OAuth 2.0 access tokens
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

#: token type identifier for JWT tokens
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"

#: token type identifiers supported by this implementation
SUPPORTED_TOKEN_TYPES = (ACCESS_TOKEN_TYPE, JWT_TOKEN_TYPE)


class TokenExchangeGrant(BaseGrant, TokenEndpointMixin):
    """The token exchange grant type defined by `RFC 8693`_. A client
    exchanges a security token (the ``subject_token``) for a new access
    token, optionally acting on behalf of another party via an
    ``actor_token``.

    When ``actor_token`` is absent, the exchange runs in **impersonation**
    mode: the granted scope converges to the intersection of the requested
    scope and the subject token's scope.

    When ``actor_token`` is present, the exchange runs in **delegation**
    mode: the granted scope converges to the intersection of the requested
    scope, the subject token's scope and the actor token's scope, so that
    a delegation chain can never widen the delegated permissions.

    Developers MUST subclass this grant and implement
    :meth:`validate_subject_token` (and :meth:`validate_actor_token` if
    delegation is enabled)::

        class MyTokenExchangeGrant(TokenExchangeGrant):
            def validate_subject_token(self, token, token_type):
                return query_token_from_database(token)

            def validate_actor_token(self, token, token_type):
                return query_token_from_database(token)


        authorization_server.register_token_exchange_grant(MyTokenExchangeGrant)

    .. _`RFC 8693`: https://tools.ietf.org/html/rfc8693
    """

    GRANT_TYPE = GRANT_TYPE

    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    #: token types accepted for ``subject_token_type``
    SUBJECT_TOKEN_TYPES = SUPPORTED_TOKEN_TYPES

    #: token types accepted for ``actor_token_type``
    ACTOR_TOKEN_TYPES = SUPPORTED_TOKEN_TYPES

    #: token types accepted for ``requested_token_type``
    REQUESTED_TOKEN_TYPES = SUPPORTED_TOKEN_TYPES

    #: ``issued_token_type`` used when the request omits ``requested_token_type``
    DEFAULT_ISSUED_TOKEN_TYPE = ACCESS_TOKEN_TYPE

    def __init__(self, request, server):
        super().__init__(request, server)
        self.subject_token = None
        self.actor_token = None
        self.requested_token_type = None

    @property
    def is_delegation(self):
        """Whether this exchange runs in delegation mode. An empty
        ``actor_token`` means impersonation, a non-empty ``actor_token``
        means delegation."""
        return self.actor_token is not None

    def validate_subject_token(self, token, token_type):
        """Validate the ``subject_token`` and resolve it into a token
        object. Developers MUST re-implement this method. The returned
        object MUST expose a ``get_scope()`` method (as described by
        :class:`~authlib.oauth2.rfc6749.TokenMixin`) so that the grant can
        converge the delegation chain scopes. Return ``None`` if the token
        is invalid, expired or revoked::

            def validate_subject_token(self, token, token_type):
                return get_token_from_database(token)

        :param token: the ``subject_token`` string of the request.
        :param token_type: the ``subject_token_type`` of the request.
        :return: token object or None.
        """
        raise NotImplementedError()

    def validate_actor_token(self, token, token_type):
        """Validate the ``actor_token`` and resolve it into a token object,
        just like :meth:`validate_subject_token`. Developers MUST
        re-implement this method to support delegation. Return ``None`` if
        the token is invalid, expired or revoked.

        :param token: the ``actor_token`` string of the request.
        :param token_type: the ``actor_token_type`` of the request.
        :return: token object or None.
        """
        raise NotImplementedError()

    def get_subject_user(self):
        """Resolve the resource owner impersonated (or acted on behalf of)
        by this exchange. By default it returns the ``user`` attribute of
        the resolved subject token, developers CAN re-implement it, e.g.
        to read the ``sub`` claim of a JWT subject token.

        :return: user object or None.
        """
        return getattr(self.subject_token, "user", None)

    def validate_token_request(self):
        """Validate the token exchange request per `Section 2.1`_ of
        RFC 8693.

        .. _`Section 2.1`: https://tools.ietf.org/html/rfc8693#section-2.1
        """
        client = self.authenticate_token_endpoint_client()
        log.debug("Validate token exchange request of %r", client)

        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(
                f"The client is not authorized to use 'grant_type={self.GRANT_TYPE}'"
            )

        self.request.client = client
        data = self.request.payload.data

        subject_token = data.get("subject_token")
        if not subject_token:
            raise InvalidRequestError("Missing 'subject_token' parameter.")
        if not isinstance(subject_token, str):
            raise InvalidRequestError("Invalid 'subject_token' parameter.")

        subject_token_type = data.get("subject_token_type")
        if not subject_token_type:
            raise InvalidRequestError("Missing 'subject_token_type' parameter.")
        if subject_token_type not in self.SUBJECT_TOKEN_TYPES:
            raise InvalidRequestError(
                f"Unsupported 'subject_token_type' value: {subject_token_type}"
            )

        actor_token = data.get("actor_token")
        actor_token_type = data.get("actor_token_type")
        if actor_token:
            if not isinstance(actor_token, str):
                raise InvalidRequestError("Invalid 'actor_token' parameter.")
            if not actor_token_type:
                raise InvalidRequestError("Missing 'actor_token_type' parameter.")
            if actor_token_type not in self.ACTOR_TOKEN_TYPES:
                raise InvalidRequestError(
                    f"Unsupported 'actor_token_type' value: {actor_token_type}"
                )
        elif actor_token_type:
            raise InvalidRequestError("Missing 'actor_token' parameter.")

        requested_token_type = data.get("requested_token_type")
        if (
            requested_token_type
            and requested_token_type not in self.REQUESTED_TOKEN_TYPES
        ):
            raise InvalidRequestError(
                f"Unsupported 'requested_token_type' value: {requested_token_type}"
            )
        self.requested_token_type = (
            requested_token_type or self.DEFAULT_ISSUED_TOKEN_TYPE
        )

        # resolve the presented security tokens
        self.subject_token = self.validate_subject_token(
            subject_token, subject_token_type
        )
        if self.subject_token is None:
            raise InvalidGrantError(
                "The 'subject_token' is invalid, expired or revoked."
            )

        if actor_token:
            self.actor_token = self.validate_actor_token(actor_token, actor_token_type)
            if self.actor_token is None:
                raise InvalidGrantError(
                    "The 'actor_token' is invalid, expired or revoked."
                )

        # converge the delegation chain scope, the rules differ between
        # impersonation (no actor_token) and delegation (with actor_token)
        self.request.scope = self.resolve_scope()
        self.request.user = self.get_subject_user()

    def resolve_scope(self):
        """Converge the requested scope with the scopes of the tokens in
        the delegation chain.

        * impersonation: requested scope is narrowed by the subject token
          scope.
        * delegation: requested scope is narrowed by the intersection of
          the subject token scope and the actor token scope.

        :return: the granted scope string.
        """
        requested_scope = self.request.payload.scope
        self.server.validate_requested_scope(requested_scope)

        chain_scopes = [_token_scopes(self.subject_token)]
        if self.is_delegation:
            chain_scopes.append(_token_scopes(self.actor_token))
        return self.converge_scope(requested_scope, chain_scopes)

    @staticmethod
    def converge_scope(requested_scope, chain_scopes):
        """Narrow the requested scope down to what every token in the
        delegation chain allows. A token without scope information does
        not restrict the chain.

        :param requested_scope: the ``scope`` parameter of the request.
        :param chain_scopes: list of scope lists, one per token in the chain.
        :return: the granted scope string.
        :raise: InvalidScopeError if the requested scope can not be
            satisfied by the delegation chain at all.
        """
        allowed = None
        for scopes in chain_scopes:
            if scopes is None:
                # token carries no scope information, it does not
                # restrict the chain
                continue
            scopes = set(scopes)
            allowed = scopes if allowed is None else allowed & scopes

        requested = scope_to_list(requested_scope)
        if allowed is None:
            return list_to_scope(requested) if requested else None

        if requested:
            granted = [scope for scope in requested if scope in allowed]
            if not granted:
                raise InvalidScopeError(
                    "The requested scope exceeds the scope of the token exchange chain."
                )
            return list_to_scope(granted)

        if allowed:
            return list_to_scope(sorted(allowed))
        return None

    @hooked
    def create_token_response(self):
        """Issue the exchanged token per `Section 2.2`_ of RFC 8693. The
        issued token is a Bearer token so that it plugs into the RFC 6750
        validation chain of resource servers.

        .. _`Section 2.2`: https://tools.ietf.org/html/rfc8693#section-2.2
        """
        token = self.generate_token(
            user=self.request.user,
            scope=self.request.scope,
            include_refresh_token=False,
        )
        # exchanged tokens are used with the "Authorization: Bearer" scheme,
        # map them onto the RFC 6750 BearerTokenValidator chain
        token["token_type"] = "Bearer"
        log.debug("Issue exchanged token %r to %r", token, self.client)
        self.save_token(token)

        body = dict(token)
        body["issued_token_type"] = self.requested_token_type
        return 200, body, self.TOKEN_RESPONSE_HEADER


def _token_scopes(token):
    get_scope = getattr(token, "get_scope", None)
    if get_scope is None:
        return None
    scope = get_scope()
    if scope is None:
        return None
    return scope_to_list(scope)
