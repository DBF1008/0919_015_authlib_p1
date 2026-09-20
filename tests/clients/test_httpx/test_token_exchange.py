import httpx
import pytest

from authlib.common.urls import url_decode
from authlib.integrations.base_client import MissingTokenError
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.httpx_client import OAuth2Client
from authlib.integrations.httpx_client import OAuthError
from authlib.oauth2.rfc8693 import ACCESS_TOKEN_TYPE
from authlib.oauth2.rfc8693 import GRANT_TYPE
from authlib.oauth2.rfc8693 import JWT_TOKEN_TYPE

TOKEN_ENDPOINT = "https://as.test/oauth/token"

exchange_response = {
    "access_token": "exchanged-access-token",
    "issued_token_type": ACCESS_TOKEN_TYPE,
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "profile",
}


def make_transport(assert_func, body=None, status_code=200):
    def handler(request):
        if assert_func:
            assert_func(request)
        return httpx.Response(status_code, json=body or exchange_response)

    return httpx.MockTransport(handler)


def parse_form(request):
    return dict(url_decode(request.content.decode()))


def test_exchange_token_impersonation():
    def assert_request(request):
        data = parse_form(request)
        assert data["grant_type"] == GRANT_TYPE
        assert data["subject_token"] == "subject-token"
        assert data["subject_token_type"] == ACCESS_TOKEN_TYPE
        assert data["scope"] == "profile"
        assert "actor_token" not in data
        assert "actor_token_type" not in data

    transport = make_transport(assert_request)
    with OAuth2Client(
        "client-id",
        "client-secret",
        token_endpoint=TOKEN_ENDPOINT,
        transport=transport,
    ) as client:
        token = client.exchange_token(
            subject_token="subject-token",
            scope="profile",
        )

    assert token["access_token"] == "exchanged-access-token"
    assert token["issued_token_type"] == ACCESS_TOKEN_TYPE
    assert token["token_type"] == "Bearer"
    assert client.token["access_token"] == "exchanged-access-token"


def test_exchange_token_delegation():
    def assert_request(request):
        data = parse_form(request)
        assert data["grant_type"] == GRANT_TYPE
        assert data["subject_token"] == "subject-token"
        assert data["actor_token"] == "actor-token"
        assert data["actor_token_type"] == ACCESS_TOKEN_TYPE

    transport = make_transport(assert_request)
    with OAuth2Client(
        "client-id",
        "client-secret",
        token_endpoint=TOKEN_ENDPOINT,
        transport=transport,
    ) as client:
        token = client.exchange_token(
            subject_token="subject-token",
            actor_token="actor-token",
        )

    assert token["access_token"] == "exchanged-access-token"


def test_exchange_token_jwt_types_and_extra_params():
    def assert_request(request):
        data = parse_form(request)
        assert data["subject_token_type"] == JWT_TOKEN_TYPE
        assert data["actor_token_type"] == JWT_TOKEN_TYPE
        assert data["requested_token_type"] == JWT_TOKEN_TYPE
        assert data["audience"] == "api.example.com"
        assert data["resource"] == "https://api.example.com"

    transport = make_transport(assert_request)
    with OAuth2Client(
        "client-id",
        "client-secret",
        token_endpoint=TOKEN_ENDPOINT,
        transport=transport,
    ) as client:
        client.exchange_token(
            url=TOKEN_ENDPOINT,
            subject_token="subject-jwt",
            subject_token_type=JWT_TOKEN_TYPE,
            actor_token="actor-jwt",
            actor_token_type=JWT_TOKEN_TYPE,
            requested_token_type=JWT_TOKEN_TYPE,
            audience="api.example.com",
            resource="https://api.example.com",
        )


def test_exchange_token_default_scope_from_client():
    def assert_request(request):
        data = parse_form(request)
        assert data["scope"] == "profile email"

    transport = make_transport(assert_request)
    with OAuth2Client(
        "client-id",
        "client-secret",
        scope="profile email",
        token_endpoint=TOKEN_ENDPOINT,
        transport=transport,
    ) as client:
        client.exchange_token(subject_token="subject-token")


def test_exchange_token_client_authentication():
    def assert_request(request):
        assert request.headers["Authorization"].startswith("Basic ")

    transport = make_transport(assert_request)
    with OAuth2Client(
        "client-id",
        "client-secret",
        token_endpoint=TOKEN_ENDPOINT,
        transport=transport,
    ) as client:
        client.exchange_token(subject_token="subject-token")


def test_exchange_token_missing_subject_token():
    with OAuth2Client(
        "client-id",
        "client-secret",
        token_endpoint=TOKEN_ENDPOINT,
        transport=make_transport(None),
    ) as client:
        with pytest.raises(MissingTokenError):
            client.exchange_token()


def test_exchange_token_error_response():
    body = {
        "error": "invalid_request",
        "error_description": "Missing 'subject_token' parameter.",
    }
    transport = make_transport(None, body=body, status_code=400)
    with OAuth2Client(
        "client-id",
        "client-secret",
        token_endpoint=TOKEN_ENDPOINT,
        transport=transport,
    ) as client:
        with pytest.raises(OAuthError) as exc_info:
            client.exchange_token(subject_token="subject-token")
    assert "invalid_request" in str(exc_info.value)


@pytest.mark.asyncio
async def test_async_exchange_token_impersonation():
    def assert_request(request):
        data = parse_form(request)
        assert data["grant_type"] == GRANT_TYPE
        assert data["subject_token"] == "subject-token"
        assert data["subject_token_type"] == ACCESS_TOKEN_TYPE
        assert data["scope"] == "profile"
        assert "actor_token" not in data

    transport = make_transport(assert_request)
    async with AsyncOAuth2Client(
        "client-id",
        "client-secret",
        token_endpoint=TOKEN_ENDPOINT,
        transport=transport,
    ) as client:
        token = await client.exchange_token(
            subject_token="subject-token",
            scope="profile",
        )

    assert token["access_token"] == "exchanged-access-token"
    assert token["issued_token_type"] == ACCESS_TOKEN_TYPE
    assert token["token_type"] == "Bearer"


@pytest.mark.asyncio
async def test_async_exchange_token_delegation():
    def assert_request(request):
        data = parse_form(request)
        assert data["subject_token"] == "subject-token"
        assert data["actor_token"] == "actor-token"
        assert data["actor_token_type"] == ACCESS_TOKEN_TYPE

    transport = make_transport(assert_request)
    async with AsyncOAuth2Client(
        "client-id",
        "client-secret",
        token_endpoint=TOKEN_ENDPOINT,
        transport=transport,
    ) as client:
        token = await client.exchange_token(
            subject_token="subject-token",
            actor_token="actor-token",
        )

    assert token["access_token"] == "exchanged-access-token"


@pytest.mark.asyncio
async def test_async_exchange_token_missing_subject_token():
    async with AsyncOAuth2Client(
        "client-id",
        "client-secret",
        token_endpoint=TOKEN_ENDPOINT,
        transport=make_transport(None),
    ) as client:
        with pytest.raises(MissingTokenError):
            await client.exchange_token()


@pytest.mark.asyncio
async def test_async_exchange_token_error_response():
    body = {"error": "invalid_grant", "error_description": "bad subject token"}
    transport = make_transport(None, body=body, status_code=400)
    async with AsyncOAuth2Client(
        "client-id",
        "client-secret",
        token_endpoint=TOKEN_ENDPOINT,
        transport=transport,
    ) as client:
        with pytest.raises(OAuthError) as exc_info:
            await client.exchange_token(subject_token="subject-token")
    assert "invalid_grant" in str(exc_info.value)
