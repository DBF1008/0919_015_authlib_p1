import pytest
from httpx import WSGITransport

from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.httpx_client import OAuth2Client
from authlib.oauth2.rfc8693 import ACCESS_TOKEN_TYPE
from authlib.oauth2.rfc8693 import JWT_TOKEN_TYPE
from authlib.oauth2.rfc8693 import TOKEN_EXCHANGE_GRANT_TYPE

from ..wsgi_helper import MockDispatch

url = "https://provider.test/token"

exchanged_token = {
    "token_type": "Bearer",
    "access_token": "exchanged-token",
    "issued_token_type": ACCESS_TOKEN_TYPE,
    "expires_in": 3600,
}


def test_exchange_token_impersonation():
    def assert_func(request):
        content = request.form
        assert content.get("grant_type") == TOKEN_EXCHANGE_GRANT_TYPE
        assert content.get("subject_token") == "subject-token"
        assert content.get("subject_token_type") == ACCESS_TOKEN_TYPE
        assert "actor_token" not in content
        assert "actor_token_type" not in content

    transport = WSGITransport(MockDispatch(exchanged_token, assert_func=assert_func))
    with OAuth2Client("foo", transport=transport) as client:
        token = client.exchange_token(url, subject_token="subject-token")
        assert token["access_token"] == "exchanged-token"
        assert token["issued_token_type"] == ACCESS_TOKEN_TYPE


def test_exchange_token_delegation():
    def assert_func(request):
        content = request.form
        assert content.get("grant_type") == TOKEN_EXCHANGE_GRANT_TYPE
        assert content.get("subject_token") == "subject-token"
        assert content.get("subject_token_type") == JWT_TOKEN_TYPE
        assert content.get("actor_token") == "actor-token"
        assert content.get("actor_token_type") == ACCESS_TOKEN_TYPE
        assert content.get("scope") == "profile"
        assert content.get("audience") == "https://api.test"

    transport = WSGITransport(MockDispatch(exchanged_token, assert_func=assert_func))
    with OAuth2Client("foo", transport=transport) as client:
        token = client.exchange_token(
            url,
            subject_token="subject-token",
            subject_token_type=JWT_TOKEN_TYPE,
            actor_token="actor-token",
            scope="profile",
            audience="https://api.test",
        )
        assert token["access_token"] == "exchanged-token"


def test_exchange_token_requires_subject_token():
    transport = WSGITransport(MockDispatch(exchanged_token))
    with OAuth2Client("foo", transport=transport) as client:
        with pytest.raises(ValueError):
            client.exchange_token(url)


async def test_async_exchange_token_impersonation():
    def assert_func(request):
        content = request.form
        assert content.get("grant_type") == TOKEN_EXCHANGE_GRANT_TYPE
        assert content.get("subject_token") == "subject-token"
        assert content.get("subject_token_type") == ACCESS_TOKEN_TYPE
        assert "actor_token" not in content

    transport = WSGITransport(MockDispatch(exchanged_token, assert_func=assert_func))
    async with AsyncOAuth2Client("foo", transport=transport) as client:
        token = await client.exchange_token(url, subject_token="subject-token")
        assert token["access_token"] == "exchanged-token"
        assert token["issued_token_type"] == ACCESS_TOKEN_TYPE


async def test_async_exchange_token_delegation():
    def assert_func(request):
        content = request.form
        assert content.get("grant_type") == TOKEN_EXCHANGE_GRANT_TYPE
        assert content.get("subject_token") == "subject-token"
        assert content.get("actor_token") == "actor-token"
        assert content.get("actor_token_type") == JWT_TOKEN_TYPE
        assert content.get("scope") == "profile email"

    transport = WSGITransport(MockDispatch(exchanged_token, assert_func=assert_func))
    async with AsyncOAuth2Client("foo", transport=transport) as client:
        token = await client.exchange_token(
            url,
            subject_token="subject-token",
            actor_token="actor-token",
            actor_token_type=JWT_TOKEN_TYPE,
            scope="profile email",
        )
        assert token["access_token"] == "exchanged-token"


async def test_async_exchange_token_requires_subject_token():
    transport = WSGITransport(MockDispatch(exchanged_token))
    async with AsyncOAuth2Client("foo", transport=transport) as client:
        with pytest.raises(ValueError):
            await client.exchange_token(url)
