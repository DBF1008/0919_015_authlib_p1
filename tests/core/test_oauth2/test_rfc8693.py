import base64

import pytest

from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749 import ResourceProtector
from authlib.oauth2.rfc6749.authorization_server import AuthorizationServer
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6750 import BearerTokenGenerator
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc8693 import ACCESS_TOKEN_TYPE
from authlib.oauth2.rfc8693 import GRANT_TYPE
from authlib.oauth2.rfc8693 import JWT_TOKEN_TYPE
from authlib.oauth2.rfc8693 import TokenExchangeGrant


class ResolvedToken:
    """A security token resolved by the grant hooks."""

    def __init__(self, scope=None, user=None):
        self.scope = scope
        self.user = user

    def get_scope(self):
        return self.scope


class MockClient:
    client_id = "client-id"

    def __init__(self, grant_types=None):
        self.grant_types = grant_types or [GRANT_TYPE]

    def get_client_id(self):
        return self.client_id

    def check_client_secret(self, secret):
        return secret == "client-secret"

    def check_endpoint_auth_method(self, method, endpoint):
        return method == "client_secret_basic"

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types

    def get_allowed_scope(self, scope):
        return scope


class MockRequest(OAuth2Request):
    def __init__(self, data, headers=None):
        super().__init__("POST", "https://as.test/oauth/token", headers=headers)
        self.payload = BasicOAuth2Payload(data)

    @property
    def form(self):
        return self.payload.data


class TokenExchangeServer(AuthorizationServer):
    def __init__(self, client, tokens):
        super().__init__()
        self._client = client
        self.tokens = tokens
        self.saved_tokens = []
        self.register_token_generator(
            "default", BearerTokenGenerator(self._generate_access_token)
        )

    @staticmethod
    def _generate_access_token(client, grant_type, user, scope):
        return "exchanged-access-token"

    def query_client(self, client_id):
        if client_id == self._client.client_id:
            return self._client
        return None

    def save_token(self, token, request):
        token = dict(token)
        token["user"] = request.user
        self.saved_tokens.append(token)

    def create_oauth2_request(self, request):
        return request

    def send_signal(self, name, *args, **kwargs):
        pass

    def handle_response(self, status, body, headers):
        return status, body, headers


class MyTokenExchangeGrant(TokenExchangeGrant):
    def validate_subject_token(self, token, token_type):
        return self.server.tokens.get(token)

    def validate_actor_token(self, token, token_type):
        return self.server.tokens.get(token)


def basic_header():
    text = base64.b64encode(b"client-id:client-secret").decode()
    return {"Authorization": f"Basic {text}"}


@pytest.fixture
def user():
    return {"sub": "user-1"}


@pytest.fixture
def tokens(user):
    return {
        "subject-token": ResolvedToken(scope="profile email", user=user),
        "actor-token": ResolvedToken(scope="email"),
    }


@pytest.fixture
def client():
    return MockClient()


@pytest.fixture
def server(client, tokens):
    server = TokenExchangeServer(client, tokens)
    server.register_token_exchange_grant(MyTokenExchangeGrant)
    return server


def exchange(server, **data):
    data.setdefault("grant_type", GRANT_TYPE)
    request = MockRequest(data, headers=basic_header())
    return server.create_token_response(request)


def test_register_token_exchange_grant(server):
    grant_types = [cls.GRANT_TYPE for cls, _ in server._token_grants]
    assert GRANT_TYPE in grant_types


def test_register_default_grant_cls(client, tokens):
    server = TokenExchangeServer(client, tokens)
    server.register_token_exchange_grant()
    grant_types = [cls.GRANT_TYPE for cls, _ in server._token_grants]
    assert GRANT_TYPE in grant_types


def test_missing_subject_token(server):
    status, body, _ = exchange(server, subject_token_type=ACCESS_TOKEN_TYPE)
    assert status == 400
    assert body["error"] == "invalid_request"
    assert "subject_token" in body["error_description"]


def test_invalid_subject_token_type_value(server):
    status, body, _ = exchange(
        server,
        subject_token=["not-a-string"],
        subject_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 400
    assert body["error"] == "invalid_request"


def test_missing_subject_token_type(server):
    status, body, _ = exchange(server, subject_token="subject-token")
    assert status == 400
    assert body["error"] == "invalid_request"
    assert "subject_token_type" in body["error_description"]


def test_unsupported_subject_token_type(server):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type="urn:ietf:params:oauth:token-type:saml2",
    )
    assert status == 400
    assert body["error"] == "invalid_request"


def test_jwt_subject_token_type(server):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=JWT_TOKEN_TYPE,
    )
    assert status == 200
    assert body["access_token"] == "exchanged-access-token"


def test_unknown_subject_token(server):
    status, body, _ = exchange(
        server,
        subject_token="unknown-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 400
    assert body["error"] == "invalid_grant"


def test_actor_token_without_actor_token_type(server):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token="actor-token",
    )
    assert status == 400
    assert body["error"] == "invalid_request"
    assert "actor_token_type" in body["error_description"]


def test_actor_token_type_without_actor_token(server):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 400
    assert body["error"] == "invalid_request"


def test_unsupported_actor_token_type(server):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token="actor-token",
        actor_token_type="urn:ietf:params:oauth:token-type:saml2",
    )
    assert status == 400
    assert body["error"] == "invalid_request"


def test_unknown_actor_token(server):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token="unknown-token",
        actor_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 400
    assert body["error"] == "invalid_grant"


def test_unsupported_requested_token_type(server):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        requested_token_type="urn:ietf:params:oauth:token-type:saml2",
    )
    assert status == 400
    assert body["error"] == "invalid_request"


def test_unauthorized_client(tokens):
    client = MockClient(grant_types=["client_credentials"])
    server = TokenExchangeServer(client, tokens)
    server.register_token_exchange_grant(MyTokenExchangeGrant)
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 400
    assert body["error"] == "unauthorized_client"


def test_invalid_client(server):
    data = {
        "grant_type": GRANT_TYPE,
        "subject_token": "subject-token",
        "subject_token_type": ACCESS_TOKEN_TYPE,
    }
    request = MockRequest(data)
    status, body, _ = server.create_token_response(request)
    assert body["error"] == "invalid_client"


def test_impersonation_scope_convergence(server):
    # impersonation: no actor_token, requested scope is narrowed by the
    # subject token scope
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        scope="profile",
    )
    assert status == 200
    assert body["scope"] == "profile"
    assert body["token_type"] == "Bearer"
    assert body["issued_token_type"] == ACCESS_TOKEN_TYPE


def test_impersonation_default_scope(server):
    # no requested scope: converge to the subject token scope
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 200
    assert body["scope"] == "email profile"


def test_impersonation_requested_token_type(server):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        requested_token_type=JWT_TOKEN_TYPE,
    )
    assert status == 200
    assert body["issued_token_type"] == JWT_TOKEN_TYPE


def test_impersonation_scope_exceeds_subject(server):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        scope="admin",
    )
    assert status == 400
    assert body["error"] == "invalid_scope"


def test_delegation_scope_convergence(server):
    # delegation: actor_token present, scope converges to the intersection
    # of subject scope ("profile email") and actor scope ("email")
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token="actor-token",
        actor_token_type=ACCESS_TOKEN_TYPE,
    )
    assert status == 200
    assert body["scope"] == "email"


def test_delegation_requested_scope_within_chain(server):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token="actor-token",
        actor_token_type=ACCESS_TOKEN_TYPE,
        scope="email",
    )
    assert status == 200
    assert body["scope"] == "email"


def test_delegation_scope_exceeds_actor(server):
    # "profile" is in the subject token scope but not in the actor token
    # scope, the delegation chain can not grant it
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token="actor-token",
        actor_token_type=ACCESS_TOKEN_TYPE,
        scope="profile",
    )
    assert status == 400
    assert body["error"] == "invalid_scope"


def test_exchanged_token_saved_with_user(server, user):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        scope="profile",
    )
    assert status == 200
    saved = server.saved_tokens[0]
    assert saved["access_token"] == "exchanged-access-token"
    assert saved["token_type"] == "Bearer"
    assert saved["scope"] == "profile"
    assert saved["user"] is user
    # "issued_token_type" is a response-only field, it MUST NOT be saved
    assert "issued_token_type" not in saved


class SavedToken:
    def __init__(self, data):
        self._data = data

    def get_scope(self):
        return self._data.get("scope")

    def is_expired(self):
        return False

    def is_revoked(self):
        return False


class ResourceRequest:
    def __init__(self, token):
        self.headers = {"Authorization": f"Bearer {token}"}


def test_exchanged_token_in_bearer_token_validator_chain(server):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        scope="profile",
    )
    assert status == 200

    class MyBearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            for saved in server.saved_tokens:
                if saved["access_token"] == token_string:
                    return SavedToken(saved)
            return None

    protector = ResourceProtector()
    protector.register_token_validator(MyBearerTokenValidator())

    request = ResourceRequest(body["access_token"])
    token = protector.validate_request(["profile"], request)
    assert token.get_scope() == "profile"


def test_exchanged_token_insufficient_scope(server):
    status, body, _ = exchange(
        server,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        scope="profile",
    )
    assert status == 200

    class MyBearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            for saved in server.saved_tokens:
                if saved["access_token"] == token_string:
                    return SavedToken(saved)
            return None

    protector = ResourceProtector()
    protector.register_token_validator(MyBearerTokenValidator())

    from authlib.oauth2.rfc6750 import InsufficientScopeError

    request = ResourceRequest(body["access_token"])
    with pytest.raises(InsufficientScopeError):
        protector.validate_request(["email"], request)
