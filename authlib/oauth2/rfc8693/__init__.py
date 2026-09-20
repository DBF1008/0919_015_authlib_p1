"""authlib.oauth2.rfc8693.
~~~~~~~~~~~~~~~~~~~~~~

This module represents an implementation of
OAuth 2.0 Token Exchange.

https://tools.ietf.org/html/rfc8693
"""

from .grant import ACCESS_TOKEN_TYPE
from .grant import GRANT_TYPE
from .grant import JWT_TOKEN_TYPE
from .grant import SUPPORTED_TOKEN_TYPES
from .grant import TokenExchangeGrant

__all__ = [
    "GRANT_TYPE",
    "ACCESS_TOKEN_TYPE",
    "JWT_TOKEN_TYPE",
    "SUPPORTED_TOKEN_TYPES",
    "TokenExchangeGrant",
]
