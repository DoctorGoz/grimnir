"""role-sweep.py screens documented reads against the roles the docs say must be refused.

What matters is what it counts as a hit (a 2xx carrying data, never an empty list or an error
object) and how it resolves a path parameter (by listing the parent collection, never by guessing),
because a wrong hit wastes a confirm run and a wrong id fires at an object nobody chose.
"""
import json
import sys

import pytest

from conftest import REPO, _load


@pytest.fixture(scope="module")
def rs():
    sys.path.insert(0, str(REPO / "scripts"))
    return _load("grimnir_role_sweep", "scripts/role-sweep.py")


class TestShape:
    def test_empty_list_is_not_data(self, rs):
        assert rs.shape(b"[]") == (0, False)

    def test_non_empty_list_is_data(self, rs):
        assert rs.shape(b'[{"id": 1}]') == (1, True)

    def test_error_object_is_not_data(self, rs):
        assert rs.shape(b'{"error": "Not Authorized"}')[1] is False

    def test_object_is_data(self, rs):
        assert rs.shape(b'{"id": 7, "name": "x"}')[1] is True


class FakeSender:
    def __init__(self, answers):
        self.answers, self.urls = answers, []

    def get(self, url, auth):
        self.urls.append(url)
        st, body = self.answers.get(url, (404, b"{}"))
        return st, body, ""


class TestFirstId:
    BASE = "https://h.example/api"

    def test_lists_the_parent_collection_and_caches(self, rs):
        s = FakeSender({f"{self.BASE}/things?per_page=5": (200, json.dumps([{"id": 42}]).encode())})
        cache = {}
        assert rs.first_id(s, self.BASE, "/things/{id}", {}, cache) == "42"
        assert rs.first_id(s, self.BASE, "/things/{id}/sub", {}, cache) == "42"
        assert len(s.urls) == 1

    def test_empty_collection_resolves_nothing(self, rs):
        s = FakeSender({f"{self.BASE}/things?per_page=5": (200, b"[]")})
        assert rs.first_id(s, self.BASE, "/things/{id}", {}, {}) is None

    def test_path_keyed_collection_uses_path(self, rs):
        s = FakeSender({f"{self.BASE}/folders?per_page=5": (200, json.dumps([{"path": "docs"}]).encode())})
        assert rs.first_id(s, self.BASE, "/folders/{path}", {}, {}) == "docs"


def test_headers_of_splits_header_lines(rs):
    assert rs.headers_of({"auth_headers": ["X-Key: abc:def", "junk"]}) == {"X-Key": "abc:def"}



class TestResolveHint:
    HINTS = [("/history/users", "77"), ("/files", "docs/a.txt")]

    def test_exact_parent_gets_the_hint(self, rs):
        assert rs.resolve_hint("/history/users/{id}", self.HINTS) == "77"

    def test_prefix_of_a_longer_parent_does_not_match(self, rs):
        assert rs.resolve_hint("/files_actions/{id}", self.HINTS) is None
        assert rs.resolve_hint("/history/{id}", self.HINTS) is None

    def test_path_without_parameter(self, rs):
        assert rs.resolve_hint("/users", self.HINTS) is None
