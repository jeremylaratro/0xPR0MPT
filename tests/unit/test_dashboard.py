"""
Dashboard API — focused regression tests for R12, R13, and R5.

R12: POST /api/corpus/regenerate now requires X-Requested-With: XMLHttpRequest
R13: GenerateRequest.count is honoured (bounded slice); response reflects actual count
R5:  Separate session cookie jars see independent generated corpora
"""

import pytest
from fastapi.testclient import TestClient

import dashboard.app as app_module
from dashboard.app import app, _SESSION_COOKIE_NAME, _SESSION_CORPUS_MAX_SIZE

XHR_HEADERS = {"X-Requested-With": "XMLHttpRequest"}


# ---------------------------------------------------------------------------
# Autouse fixture: reset all session/cache state between tests so test
# isolation is guaranteed even when they run in a single process.
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _reset_state():
    """Clear LRU cache and session store before (and after) every test."""
    app_module.get_all_test_cases.cache_clear()
    app_module._session_corpora.clear()
    yield
    app_module.get_all_test_cases.cache_clear()
    app_module._session_corpora.clear()


# ---------------------------------------------------------------------------
# R12 — POST /api/corpus/regenerate requires XHR header
# ---------------------------------------------------------------------------

class TestR12RegenerateXHRGuard:

    def test_regenerate_without_xhr_header_is_rejected(self):
        """Missing X-Requested-With must return 403."""
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.post("/api/corpus/regenerate")
        assert resp.status_code == 403, (
            f"Expected 403 without XHR header, got {resp.status_code}: {resp.text}"
        )

    def test_regenerate_with_xhr_header_succeeds(self):
        """Correct X-Requested-With header must return 200."""
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.post("/api/corpus/regenerate", headers=XHR_HEADERS)
        assert resp.status_code == 200, (
            f"Expected 200 with XHR header, got {resp.status_code}: {resp.text}"
        )
        assert resp.json().get("ok") is True

    def test_regenerate_wrong_xhr_value_is_rejected(self):
        """A wrong value for X-Requested-With must still return 403."""
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.post(
                "/api/corpus/regenerate",
                headers={"X-Requested-With": "fetch"},
            )
        assert resp.status_code == 403

    def test_generate_without_xhr_header_is_rejected(self):
        """Sibling route /api/corpus/generate also guards with XHR header."""
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.post(
                "/api/corpus/generate",
                json={"categories": None, "count": None, "target": None},
            )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# R13 — GenerateRequest.count is honoured
# ---------------------------------------------------------------------------

class TestR13CountHonoured:

    def test_count_none_returns_full_corpus(self):
        """No count → all cases are returned."""
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.post(
                "/api/corpus/generate",
                json={"count": None, "target": None},
                headers=XHR_HEADERS,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] > 0
        # count must equal sum of category counts
        assert data["count"] == sum(data["categories"].values())

    def test_count_is_bounded(self):
        """count=5 → response count == 5 and per-category sum == 5."""
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.post(
                "/api/corpus/generate",
                json={"count": 5, "target": None},
                headers=XHR_HEADERS,
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 5, f"Expected 5, got {data['count']}"
        assert sum(data["categories"].values()) == 5

    def test_count_capped_at_total(self):
        """count larger than total → response count == total (not more)."""
        with TestClient(app, raise_server_exceptions=True) as client:
            # Get total first
            full_resp = client.post(
                "/api/corpus/generate",
                json={"count": None, "target": None},
                headers=XHR_HEADERS,
            )
        full_total = full_resp.json()["count"]

        app_module.get_all_test_cases.cache_clear()
        app_module._session_corpora.clear()

        with TestClient(app, raise_server_exceptions=True) as client:
            capped_resp = client.post(
                "/api/corpus/generate",
                json={"count": full_total + 9999, "target": None},
                headers=XHR_HEADERS,
            )
        assert capped_resp.json()["count"] == full_total

    def test_count_zero_is_treated_as_no_limit(self):
        """count=0 is falsy → treated the same as None (no limit)."""
        with TestClient(app, raise_server_exceptions=True) as client:
            resp_zero = client.post(
                "/api/corpus/generate",
                json={"count": 0, "target": None},
                headers=XHR_HEADERS,
            )
        app_module.get_all_test_cases.cache_clear()
        app_module._session_corpora.clear()

        with TestClient(app, raise_server_exceptions=True) as client:
            resp_none = client.post(
                "/api/corpus/generate",
                json={"count": None, "target": None},
                headers=XHR_HEADERS,
            )
        # Both should return the full corpus
        assert resp_zero.json()["count"] == resp_none.json()["count"]

    def test_negative_count_is_treated_as_no_limit(self):
        """count<0 fails the `> 0` guard → treated as no limit (like None); must not crash."""
        with TestClient(app, raise_server_exceptions=True) as client:
            resp_neg = client.post(
                "/api/corpus/generate",
                json={"count": -5, "target": None},
                headers=XHR_HEADERS,
            )
        app_module.get_all_test_cases.cache_clear()
        app_module._session_corpora.clear()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp_none = client.post(
                "/api/corpus/generate",
                json={"count": None, "target": None},
                headers=XHR_HEADERS,
            )
        assert resp_neg.status_code == 200
        assert resp_neg.json()["count"] == resp_none.json()["count"]

    def test_subsequent_corpus_api_reflects_bounded_count(self):
        """After generate with count=3, GET /api/corpus returns 3 items for that session."""
        with TestClient(app, raise_server_exceptions=True) as client:
            gen_resp = client.post(
                "/api/corpus/generate",
                json={"count": 3, "target": None},
                headers=XHR_HEADERS,
            )
            assert gen_resp.status_code == 200
            assert gen_resp.json()["count"] == 3

            # Same client (same cookie jar) — /api/corpus should reflect 3
            corpus_resp = client.get("/api/corpus")
        assert corpus_resp.status_code == 200
        assert corpus_resp.json()["count"] == 3


# ---------------------------------------------------------------------------
# R5 — Session isolation: two clients with different cookie jars
# ---------------------------------------------------------------------------

class TestR5SessionIsolation:

    def test_two_clients_see_independent_corpora(self):
        """
        Behavioral isolation: client A generates a 5-case corpus, client B a
        10-case corpus. With BOTH sessions live, each client's GET /api/corpus
        must reflect ONLY its own corpus (A sees 5, B sees 10). This FAILS if
        one session's generate bleeds into the other's view.
        """
        with TestClient(app, raise_server_exceptions=True) as client_a, \
                TestClient(app, raise_server_exceptions=True) as client_b:
            gen_a = client_a.post(
                "/api/corpus/generate",
                json={"count": 5, "target": "ALPHA_TARGET"},
                headers=XHR_HEADERS,
            )
            gen_b = client_b.post(
                "/api/corpus/generate",
                json={"count": 10, "target": "BETA_TARGET"},
                headers=XHR_HEADERS,
            )
            assert gen_a.status_code == 200 and gen_b.status_code == 200
            assert gen_a.json()["count"] == 5
            assert gen_b.json()["count"] == 10

            # The decisive isolation check: each client reads back its OWN size,
            # not the other's. If B's generate had bled into A, A would see 10.
            a_corpus = client_a.get("/api/corpus").json()
            b_corpus = client_b.get("/api/corpus").json()
            assert a_corpus["count"] == 5, (
                f"client A must see its own 5-case corpus, saw {a_corpus['count']} "
                "(cross-session bleed)"
            )
            assert b_corpus["count"] == 10, (
                f"client B must see its own 10-case corpus, saw {b_corpus['count']} "
                "(cross-session bleed)"
            )

            # Distinct opaque session cookies were minted for each client.
            cookie_a = client_a.cookies.get(_SESSION_COOKIE_NAME)
            cookie_b = client_b.cookies.get(_SESSION_COOKIE_NAME)
            assert cookie_a and cookie_b and cookie_a != cookie_b, (
                "Each client must get its own distinct session cookie"
            )
        assert len(app_module._session_corpora) == 2

    def test_client_without_session_falls_back_to_default(self):
        """A fresh client (no cookie) gets the default canonical corpus."""
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.get("/api/corpus")
        assert resp.status_code == 200
        assert resp.json()["count"] > 0

    def test_regenerate_only_clears_calling_sessions_corpus(self):
        """
        Client A regenerates.  Client B's session corpus must be unaffected.
        """
        # Client B sets up a bounded corpus
        with TestClient(app, raise_server_exceptions=True) as client_b:
            client_b.post(
                "/api/corpus/generate",
                json={"count": 7, "target": None},
                headers=XHR_HEADERS,
            )
            b_count_before = client_b.get("/api/corpus").json()["count"]
            assert b_count_before == 7

        # Client A regenerates (should only clear A's session)
        with TestClient(app, raise_server_exceptions=True) as client_a:
            client_a.post(
                "/api/corpus/generate",
                json={"count": 4, "target": None},
                headers=XHR_HEADERS,
            )
            client_a.post("/api/corpus/regenerate", headers=XHR_HEADERS)
            # After regenerate, client A falls back to the canonical corpus
            a_corpus_after = client_a.get("/api/corpus")

        # Client B's session must still be in the store
        with TestClient(app, raise_server_exceptions=True) as client_b_check:
            # We need to re-supply the cookie, but TestClient doesn't persist
            # between `with` blocks.  Instead, verify via the internal store:
            # Client B's session key is still in _session_corpora
            stored_counts = [len(v) for v in app_module._session_corpora.values()]
        assert 7 in stored_counts, (
            "Client B's corpus (7 items) should still be in the session store "
            f"after client A regenerated. Store counts: {stored_counts}"
        )

    def test_session_store_size_cap_evicts_oldest(self):
        """When _SESSION_CORPUS_MAX_SIZE is reached, oldest session is evicted."""
        # Fill the store to the cap with tiny corpora
        for i in range(_SESSION_CORPUS_MAX_SIZE):
            # Directly inject sessions to avoid spinning up many TestClients
            key = f"fake_session_{i}"
            app_module._session_corpora[key] = []

        assert len(app_module._session_corpora) == _SESSION_CORPUS_MAX_SIZE
        first_key = next(iter(app_module._session_corpora))

        # One more client generates → the oldest must be evicted
        with TestClient(app, raise_server_exceptions=True) as client:
            client.post(
                "/api/corpus/generate",
                json={"count": 1, "target": None},
                headers=XHR_HEADERS,
            )

        assert first_key not in app_module._session_corpora, (
            "Oldest session should have been evicted when cap was reached"
        )
        assert len(app_module._session_corpora) == _SESSION_CORPUS_MAX_SIZE
