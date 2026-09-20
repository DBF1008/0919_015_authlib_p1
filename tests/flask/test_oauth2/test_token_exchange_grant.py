import pytest
from flask import json
from flask import jsonify

from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2.rfc8693 import ACCESS_TOKEN_TYPE
from authlib.oauth2.rfc8693 import JWT_TOKEN_TYPE
from authlib.oauth2.rfc8693 import TOKEN_EXCHANGE_GRANT_TYPE
from authlib.oauth2.rfc8693 import TokenExchangeBearerTokenValidator
from authlib.oauth2.rfc8693 import TokenExchangeGrant

from .models import Token
from .models import User
from .oauth2_server import create_basic_header
from .oauth2_server import create_bearer_header


class MyTokenExchangeGrant(TokenExchangeGrant):
    def resolve_subject_token(self, token, token_type):
        return self._resolve(token)

    def resolve_actor_token(self, token, token_type):
        return self._resolve(token)

    @staticmethod
    def _resolve(token):
        item = Token.query.filter_by(access_token=token).first()
        if item and not item.is_expired() and not item.is_revoked():
            return {"user": item.user, "scope": item.scope}
        return None


@pytest.fixture(autouse=True)
def server(server):
    server.register_token_exchange_grant(MyTokenExchangeGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile email",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": [TOKEN_EXCHANGE_GRANT_TYPE],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture
def subject_token(db, user):
    item = Token(
        user_id=user.id,
        client_id="client-id",
        token_type="Bearer",
        access_token="subject-token",
        scope="profile email",
        expires_in=3600,
    )
    db.session.add(item)
    db.session.commit()
    yield item
    db.session.delete(item)
    db.session.commit()


@pytest.fixture
def actor_token(db):
    actor = User(username="actor")
    db.session.add(actor)
    db.session.commit()
    item = Token(
        user_id=actor.id,
        client_id="client-id",
        token_type="Bearer",
        access_token="actor-token",
        scope="profile",
        expires_in=3600,
    )
    db.session.add(item)
    db.session.commit()
    yield item
    db.session.delete(item)
    db.session.delete(actor)
    db.session.commit()


@pytest.fixture(autouse=True)
def resource_server(app, db):
    require_oauth = ResourceProtector()

    class _Validator(TokenExchangeBearerTokenValidator):
        def authenticate_token(self, token_string):
            return Token.query.filter_by(access_token=token_string).first()

    require_oauth.register_token_validator(_Validator())

    @app.route("/user")
    @require_oauth("profile")
    def user_profile():
        user = current_token.user
        return jsonify(id=user.id, username=user.username)

    @app.route("/user/email")
    @require_oauth("email")
    def user_email():
        user = current_token.user
        return jsonify(email=user.username + "@example.com")


def exchange_request(test_client, **data):
    data.setdefault("grant_type", TOKEN_EXCHANGE_GRANT_TYPE)
    headers = create_basic_header("client-id", "client-secret")
    return test_client.post("/oauth/token", data=data, headers=headers)


def test_missing_subject_token(test_client):
    rv = exchange_request(test_client)
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_missing_subject_token_type(test_client):
    rv = exchange_request(test_client, subject_token="subject-token")
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_unsupported_subject_token_type(test_client):
    rv = exchange_request(
        test_client,
        subject_token="subject-token",
        subject_token_type="urn:example:token-type:unknown",
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_actor_token_without_type(test_client, subject_token):
    rv = exchange_request(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token="actor-token",
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_request"


def test_invalid_subject_token(test_client):
    rv = exchange_request(
        test_client,
        subject_token="invalid-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_invalid_actor_token(test_client, subject_token):
    rv = exchange_request(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token="invalid-token",
        actor_token_type=ACCESS_TOKEN_TYPE,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_grant"


def test_unauthorized_client(test_client, client, db, subject_token):
    client.set_client_metadata(
        {
            "scope": "profile email",
            "redirect_uris": ["https://client.test/authorized"],
            "grant_types": ["client_credentials"],
        }
    )
    db.session.add(client)
    db.session.commit()
    rv = exchange_request(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "unauthorized_client"


def test_impersonation_default_scope(test_client, subject_token):
    rv = exchange_request(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 200
    assert resp["token_type"] == "Bearer"
    assert resp["issued_token_type"] == ACCESS_TOKEN_TYPE
    assert resp["scope"] == "profile email"
    assert "access_token" in resp


def test_impersonation_with_jwt_token_type(test_client, subject_token):
    rv = exchange_request(
        test_client,
        subject_token="subject-token",
        subject_token_type=JWT_TOKEN_TYPE,
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 200
    assert resp["issued_token_type"] == ACCESS_TOKEN_TYPE


def test_impersonation_narrowed_scope(test_client, subject_token):
    rv = exchange_request(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        scope="profile",
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 200
    assert resp["scope"] == "profile"


def test_impersonation_widening_rejected(test_client, subject_token):
    rv = exchange_request(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        scope="profile admin",
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_scope"


def test_delegation_scope_convergence(test_client, subject_token, actor_token):
    # subject scope: "profile email", actor scope: "profile"
    # the granted scope is narrowed to the intersection: "profile"
    rv = exchange_request(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token="actor-token",
        actor_token_type=ACCESS_TOKEN_TYPE,
    )
    resp = json.loads(rv.data)
    assert rv.status_code == 200
    assert resp["scope"] == "profile"
    assert resp["issued_token_type"] == ACCESS_TOKEN_TYPE


def test_delegation_widening_rejected(test_client, subject_token, actor_token):
    # "email" is in the subject scope but not in the actor scope
    rv = exchange_request(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token="actor-token",
        actor_token_type=ACCESS_TOKEN_TYPE,
        scope="email",
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_scope"


def test_exchanged_token_on_resource_server(test_client, subject_token):
    rv = exchange_request(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
    )
    resp = json.loads(rv.data)
    access_token = resp["access_token"]

    headers = create_bearer_header(access_token)
    rv = test_client.get("/user", headers=headers)
    assert rv.status_code == 200
    assert json.loads(rv.data)["username"] == "foo"

    rv = test_client.get("/user/email", headers=headers)
    assert rv.status_code == 200


def test_narrowed_token_on_resource_server(test_client, subject_token):
    rv = exchange_request(
        test_client,
        subject_token="subject-token",
        subject_token_type=ACCESS_TOKEN_TYPE,
        scope="profile",
    )
    resp = json.loads(rv.data)
    access_token = resp["access_token"]

    headers = create_bearer_header(access_token)
    rv = test_client.get("/user", headers=headers)
    assert rv.status_code == 200

    # the exchanged token was narrowed to "profile", it can not
    # access resources that require the "email" scope
    rv = test_client.get("/user/email", headers=headers)
    assert rv.status_code == 403
