"""openapi-to-assetmap.py converts an OpenAPI 3.x spec into asset-map endpoints[] records that the
authed-corpus chain (route-classify -> owned-id-discover -> lane-synth -> attack-plan) already
consumes. The failures that would be silent -- a wrong record that still exits 0 -- are: (1) a
requestBody $ref/allOf not resolved so body_fields comes back empty and no BOPLA lane is ever
synthesized, (2) values leaking into the corpus instead of NAMES only, (3) an operation's public
override (security:[]) misread as authed so a BFLA candidate is invented, (4) a merge that demotes a
live authed-crawl row to the static spec or drops prior recon, (5) a native `{wallet_id}` template not
surviving into a record lane-synth can bind. Each is pinned below."""


class TestOperationExtraction:
    def test_id_bearing_get_keeps_native_placeholder_and_inherits_global_auth(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        spec = {
            "servers": [{"url": "https://api.x.io"}],
            "security": [{"appSecretAuth": []}],
            "paths": {"/v1/wallets/{wallet_id}": {"get": {"tags": ["Wallets"]}}},
        }
        eps = m.openapi_to_endpoints(spec)
        assert len(eps) == 1
        ep = eps[0]
        assert ep["url"] == "https://api.x.io/v1/wallets/{wallet_id}"
        assert ep["method"] == "GET" and ep["source"] == "openapi"
        assert ep["auth_required"] is True and ep["tags"] == ["Wallets"]

    def test_query_params_captured_path_params_are_not(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        spec = {"servers": [{"url": "https://api.x.io"}],
                "paths": {"/v1/wallets/{wallet_id}/transactions": {"get": {"parameters": [
                    {"name": "wallet_id", "in": "path"},
                    {"name": "cursor", "in": "query"},
                    {"name": "limit", "in": "query"}]}}}}
        ep = m.openapi_to_endpoints(spec)[0]
        assert ep["parameters"] == ["cursor", "limit"]  # sorted, path param excluded

    def test_public_override_reads_as_no_auth(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        spec = {"security": [{"appSecretAuth": []}],
                "servers": [{"url": "https://api.x.io"}],
                "paths": {"/v1/auth/login": {"post": {"security": []}}}}
        ep = m.openapi_to_endpoints(spec)[0]
        assert ep["auth_required"] is False

    def test_optional_security_empty_object_is_not_required(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        spec = {"servers": [{"url": "https://api.x.io"}],
                "paths": {"/v1/ping": {"get": {"security": [{}]}}}}
        assert m.openapi_to_endpoints(spec)[0]["auth_required"] is False

    def test_no_global_no_op_security_defaults_public(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        spec = {"servers": [{"url": "https://api.x.io"}], "paths": {"/v1/ping": {"get": {}}}}
        assert m.openapi_to_endpoints(spec)[0]["auth_required"] is False

    def test_server_override(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        spec = {"servers": [{"url": "https://api.x.io"}], "paths": {"/v1/ping": {"get": {}}}}
        ep = m.openapi_to_endpoints(spec, server_override="https://staging.x.io")[0]
        assert ep["url"] == "https://staging.x.io/v1/ping"


class TestBodyFieldHarvest:
    def test_ref_body_resolves_to_field_names_only(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        spec = {
            "servers": [{"url": "https://api.x.io"}],
            "components": {"schemas": {"NewWallet": {"type": "object", "properties": {
                "chain_type": {"type": "string", "example": "ethereum"},  # example value must NOT leak
                "policy_ids": {"type": "array"}}}}},
            "paths": {"/v1/wallets": {"post": {"requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/NewWallet"}}}}}}},
        }
        ep = m.openapi_to_endpoints(spec)[0]
        assert ep["body_fields"] == ["chain_type", "policy_ids"]
        # names only -- no example value anywhere in the record
        assert "ethereum" not in json_dumps(ep)

    def test_allof_composition_unions_member_fields(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        spec = {
            "servers": [{"url": "https://api.x.io"}],
            "components": {"schemas": {
                "A": {"properties": {"a1": {}, "a2": {}}},
                "B": {"properties": {"b1": {}}}}},
            "paths": {"/v1/x": {"post": {"requestBody": {"content": {"application/json": {"schema": {
                "allOf": [{"$ref": "#/components/schemas/A"}, {"$ref": "#/components/schemas/B"}]}}}}}}},
        }
        ep = m.openapi_to_endpoints(spec)[0]
        assert ep["body_fields"] == ["a1", "a2", "b1"]

    def test_array_body_descends_into_items(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        spec = {"servers": [{"url": "https://api.x.io"}],
                "paths": {"/v1/bulk": {"post": {"requestBody": {"content": {"application/json": {
                    "schema": {"type": "array", "items": {"properties": {"id": {}, "role": {}}}}}}}}}}}
        ep = m.openapi_to_endpoints(spec)[0]
        assert ep["body_fields"] == ["id", "role"]

    def test_broken_ref_fails_open_no_crash(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        assert m.schema_field_names({}, {"$ref": "#/components/schemas/Missing"}) == []
        assert m.schema_field_names({}, {"$ref": "https://external/schema.json"}) == []

    def test_ref_cycle_terminates(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        spec = {"components": {"schemas": {"Node": {"allOf": [{"$ref": "#/components/schemas/Node"}],
                                                    "properties": {"val": {}}}}}}
        # must not recurse forever; returns the reachable field name(s)
        assert m.schema_field_names(spec, {"$ref": "#/components/schemas/Node"}) == ["val"]


class TestMerge:
    def test_live_source_not_demoted_and_recon_preserved(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        existing = [{"url": "https://api.x.io/v1/wallets/{wallet_id}", "method": "GET",
                     "source": "authed-crawl", "auth_required": True, "tags": ["seed"]}]
        incoming = [{"url": "https://api.x.io/v1/wallets/{wallet_id}", "method": "GET",
                     "source": "openapi", "tags": ["Wallets"]}]
        row = _get(m.merge_endpoints(existing, incoming), "GET", "{wallet_id}")
        assert row["source"] == "authed-crawl"          # never demoted to the static spec
        assert set(row["tags"]) == {"seed", "Wallets"}   # unioned, prior recon kept

    def test_new_openapi_row_appended_and_idempotent(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        incoming = [{"url": "https://api.x.io/v1/users/{user_id}", "method": "GET",
                     "source": "openapi", "auth_required": True}]
        once = m.merge_endpoints([], incoming)
        twice = m.merge_endpoints(once, incoming)
        assert len(once) == len(twice) == 1 and once[0]["source"] == "openapi"

    def test_auth_required_is_ored_true(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        existing = [{"url": "https://api.x.io/v1/x", "method": "GET", "auth_required": False}]
        incoming = [{"url": "https://api.x.io/v1/x", "method": "GET", "auth_required": True}]
        assert m.merge_endpoints(existing, incoming)[0]["auth_required"] is True


class TestIngest:
    def test_ingest_preserves_target_and_fills_endpoints(self, openapi_assetmap_mod):
        m = openapi_assetmap_mod
        spec = {"servers": [{"url": "https://api.x.io"}],
                "security": [{"appSecretAuth": []}],
                "paths": {"/v1/wallets/{wallet_id}": {"get": {}}}}
        am = {"target": "api.x.io", "endpoints": [], "technologies": [{"name": "nginx"}]}
        out = m.ingest(spec, am)
        assert out["target"] == "api.x.io" and out["technologies"] == [{"name": "nginx"}]
        assert len(out["endpoints"]) == 1 and out["endpoints"][0]["method"] == "GET"


def _get(rows, method, url_suffix):
    return next(e for e in rows if e["method"] == method and e["url"].endswith(url_suffix))


def json_dumps(o):
    import json
    return json.dumps(o)
