"""authlib.oauth2.rfc8693.
~~~~~~~~~~~~~~~~~~~~~~

This module represents an implementation of
OAuth 2.0 Token Exchange.

https://tools.ietf.org/html/rfc8693
"""

import logging

from ..rfc6749 import BaseGrant
from ..rfc6749 import InvalidGrantError
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import InvalidScopeError
from ..rfc6749 import TokenEndpointMixin
from ..rfc6749 import UnauthorizedClientError
from ..rfc6749 import list_to_scope
from ..rfc6749 import scope_to_list
from ..rfc6749.hooks import hooked
from ..rfc6750 import BearerTokenValidator

log = logging.getLogger(__name__)

#: Grant type for OAuth 2.0 Token Exchange
TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"

#: Token type identifier for OAuth 2.0 access tokens
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

#: Token type identifier for JSON Web Tokens
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"


class TokenExchangeGrant(BaseGrant, TokenEndpointMixin):
    """The OAuth 2.0 Token Exchange grant, per `RFC 8693`_.

    A client requests a security token by presenting a ``subject_token``
    (and optionally an ``actor_token``) to the token endpoint::

        POST /token HTTP/1.1
        Host: server.example.com
        Content-Type: application/x-www-form-urlencoded

        grant_type=urn:ietf:params:oauth:grant-type:token-exchange
        &subject_token=eyJhbGciOiJFUzI1NiIsIm...
        &subject_token_type=urn:ietf:params:oauth:token-type:jwt

    When no ``actor_token`` is present, the exchange is an
    **impersonation**: the issued token represents the subject. When an
    ``actor_token`` is present, the exchange is a **delegation**: the
    actor acts on behalf of the subject, and the granted scope is
    narrowed to the intersection of the subject and actor scopes.

    Developers MUST implement :meth:`resolve_subject_token` and
    :meth:`resolve_actor_token` to map the presented tokens to a user
    and a scope.

    .. _`RFC 8693`: https://tools.ietf.org/html/rfc8693
    """

    GRANT_TYPE = TOKEN_EXCHANGE_GRANT_TYPE

    #: Token types accepted for ``subject_token_type`` and
    #: ``actor_token_type``.
    SUPPORTED_TOKEN_TYPES = (ACCESS_TOKEN_TYPE, JWT_TOKEN_TYPE)

    #: Value of the ``issued_token_type`` parameter in token responses.
    ISSUED_TOKEN_TYPE = ACCESS_TOKEN_TYPE

    def validate_token_request(self):
        """Validate the token exchange request, per `Section 2.1`_.

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
        subject_token_type = data.get("subject_token_type")
        if not subject_token:
            raise InvalidRequestError("Missing 'subject_token' in request.")
        if not subject_token_type:
            raise InvalidRequestError("Missing 'subject_token_type' in request.")
        self._validate_token_type("subject_token_type", subject_token_type)

        actor_token = data.get("actor_token")
        actor_token_type = data.get("actor_token_type")
        if actor_token and not actor_token_type:
            raise InvalidRequestError("Missing 'actor_token_type' in request.")
        if actor_token_type and not actor_token:
            raise InvalidRequestError("Missing 'actor_token' in request.")
        if actor_token:
            self._validate_token_type("actor_token_type", actor_token_type)

        self.subject = self.resolve_subject_token(subject_token, subject_token_type)
        if self.subject is None:
            raise InvalidGrantError("The 'subject_token' is invalid or expired.")

        if actor_token:
            self.actor = self.resolve_actor_token(actor_token, actor_token_type)
            if self.actor is None:
                raise InvalidGrantError("The 'actor_token' is invalid or expired.")
        else:
            self.actor = None

        self.scope = self._resolve_requested_scope()
        self.server.validate_requested_scope(self.scope)

    @hooked
    def create_token_response(self):
        """Issue a new token for the exchange, per `Section 2.2`_.

        The response contains the ``issued_token_type`` parameter to
        indicate the type of the issued token.

        .. _`Section 2.2`: https://tools.ietf.org/html/rfc8693#section-2.2
        """
        user = self.subject.get("user")
        self.request.user = user
        token = self.generate_token(
            user=user, scope=self.scope, include_refresh_token=False
        )
        log.debug("Issue token %r to %r", token, self.client)
        self.save_token(token)
        token["issued_token_type"] = self.ISSUED_TOKEN_TYPE
        return 200, token, self.TOKEN_RESPONSE_HEADER

    @property
    def is_delegation(self):
        """Whether this exchange is a delegation (actor token present)."""
        return self.actor is not None

    def get_delegation_chain(self):
        """Return the delegation chain of the exchange, from subject to
        actor. For impersonation the chain only contains the subject.
        """
        chain = [self.subject.get("user")]
        if self.actor is not None:
            chain.append(self.actor.get("user"))
        return chain

    def resolve_subject_token(self, token, token_type):
        """Resolve the ``subject_token`` into a dict containing the
        resource owner and the scope bound to the token::

            def resolve_subject_token(self, token, token_type):
                item = Token.query.filter_by(access_token=token).first()
                if item and not item.is_expired():
                    return {"user": item.user, "scope": item.scope}

        :param token: the ``subject_token`` value in the request.
        :param token_type: the ``subject_token_type`` value in the request,
            one of :data:`ACCESS_TOKEN_TYPE` or :data:`JWT_TOKEN_TYPE`.
        :return: a dict with ``user`` and ``scope`` keys, or ``None`` if
            the token is invalid.
        """
        raise NotImplementedError()

    def resolve_actor_token(self, token, token_type):
        """Resolve the ``actor_token`` into a dict containing the acting
        party and the scope bound to the token. Same contract as
        :meth:`resolve_subject_token`.
        """
        raise NotImplementedError()

    def _validate_token_type(self, name, value):
        if value not in self.SUPPORTED_TOKEN_TYPES:
            raise InvalidRequestError(
                f"Unsupported '{name}' value: {value}.",
            )

    def _resolve_requested_scope(self):
        """Compute the granted scope by narrowing the requested scope
        along the delegation chain.

        * Impersonation (no actor token): the granted scope is the
          requested scope constrained by the subject token scope.
        * Delegation (actor token present): the granted scope is the
          requested scope constrained by the intersection of the
          subject and actor token scopes.
        """
        requested = scope_to_list(self.request.payload.scope) or []
        subject_scope = scope_to_list(self.subject.get("scope")) or []

        if self.actor is None:
            allowed = subject_scope
        else:
            actor_scope = scope_to_list(self.actor.get("scope")) or []
            allowed = [s for s in subject_scope if s in actor_scope]

        if not requested:
            return list_to_scope(allowed)

        if allowed and not set(requested).issubset(set(allowed)):
            raise InvalidScopeError(
                "The requested scope exceeds the scope of the delegation chain."
            )
        return list_to_scope(requested)


class TokenExchangeBearerTokenValidator(BearerTokenValidator):
    """Bearer token validator for tokens issued via token exchange.

    Tokens obtained through :class:`TokenExchangeGrant` are ordinary
    bearer tokens whose scope has already been narrowed at issuance
    time. This validator plugs them into the RFC 6750 validation chain
    so that resource servers can recognize exchanged tokens exactly
    like any other bearer token.
    """

    @staticmethod
    def is_exchanged_token(token):
        """Check if the given token was issued via token exchange."""
        issued_token_type = getattr(token, "issued_token_type", None)
        if issued_token_type is None and isinstance(token, dict):
            issued_token_type = token.get("issued_token_type")
        return issued_token_type == ACCESS_TOKEN_TYPE


__all__ = [
    "TOKEN_EXCHANGE_GRANT_TYPE",
    "ACCESS_TOKEN_TYPE",
    "JWT_TOKEN_TYPE",
    "TokenExchangeGrant",
    "TokenExchangeBearerTokenValidator",
]
