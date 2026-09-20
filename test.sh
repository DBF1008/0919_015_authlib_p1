#!/bin/sh
# Run the unit tests for the RFC 8693 OAuth 2.0 Token Exchange feature.
#
# Usage:
#   ./test.sh
#
# Requires the test dependencies (pytest, pytest-asyncio, flask,
# flask-sqlalchemy, httpx, joserfc, cachelib) to be installed, e.g.:
#
#   pip install -e ".[test]"

set -e

cd "$(dirname "$0")"

echo "==> Server-side: TokenExchangeGrant (RFC 8693)"
python -m pytest tests/flask/test_oauth2/test_token_exchange_grant.py -v

echo "==> Client-side: httpx OAuth2Client.exchange_token"
python -m pytest tests/clients/test_httpx/test_token_exchange_client.py -v

echo "==> Regression: existing OAuth2 server and httpx client tests"
python -m pytest tests/flask/test_oauth2/test_client_credentials_grant.py -v
python -m pytest tests/clients/test_httpx/test_oauth2_client.py -v
python -m pytest tests/clients/test_httpx/test_async_oauth2_client.py -v

echo "All token exchange tests passed."
