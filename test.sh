#!/bin/sh
# Manual test script for the RFC 8693 OAuth 2.0 Token Exchange feature.
#
# Runs all unit tests covering:
#   1. authlib/oauth2/rfc8693                (TokenExchangeGrant, scope convergence)
#   2. authlib/oauth2/rfc6749                (register_token_exchange_grant)
#   3. authlib/integrations/httpx_client     (sync/async exchange_token)
#   4. authlib/oauth2/rfc6750                (BearerTokenValidator chain regression)
#
# Note: this offline environment has no joserfc/flask/werkzeug packages, so
# jose-dependent suites (rfc7523, rfc8414, rfc9068) and flask/wsgi based
# suites can not run here. A minimal import-only joserfc stub lives in
# .venv/lib/python3.14/site-packages/joserfc/ for local testing only.
set -e
cd "$(dirname "$0")"

PY=.venv/bin/python

echo "== RFC 8693 token exchange grant (authorization server) =="
$PY -m pytest tests/core/test_oauth2/test_rfc8693.py -v

echo "== RFC 8693 token exchange client (httpx, sync + async) =="
$PY -m pytest tests/clients/test_httpx/test_token_exchange.py -v

echo "== Regression: RFC 6750 bearer token & RFC 6749 misc =="
$PY -m pytest tests/core/test_oauth2/test_rfc6750.py tests/core/test_oauth2/test_rfc6749_misc.py -v

echo "== Regression: existing async httpx OAuth2 client =="
$PY -m pytest tests/clients/test_httpx/test_async_oauth2_client.py -v

echo "All token exchange tests passed."
