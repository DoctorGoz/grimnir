"""Make scripts/ importable as modules.

The scripts are CLIs with hyphenated names and no package, so import them by path.
Everything tested here is pure logic -- parsing, matching, resolution, scoring -- which
is exactly the code whose failures are silent: a wrong number that still exits 0.
"""
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load(name: str, relpath: str):
    if not (REPO / relpath).exists():  # public cut: component not shipped
        import pytest
        pytest.skip(f"{relpath} is not part of this build")
    spec = importlib.util.spec_from_file_location(name, REPO / relpath)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


import pytest


@pytest.fixture(scope="session")
def coverage_mod():
    return _load("grimnir_coverage", "scripts/coverage.py")


@pytest.fixture(scope="session")
def vault_project_mod():
    return _load("grimnir_vault_project", "scripts/vault-project.py")


@pytest.fixture(scope="session")
def watchstander_mod():
    return _load("grimnir_watchstander", "scripts/watchstander.py")


@pytest.fixture(scope="session")
def outcomes_mod():
    return _load("grimnir_outcomes", "scripts/outcomes.py")


@pytest.fixture(scope="session")
def export_mod():
    return _load("grimnir_export", "scripts/export-findings.py")


@pytest.fixture(scope="session")
def credqueue_mod():
    return _load("grimnir_credqueue", "scripts/credqueue.py")


@pytest.fixture(scope="session")
def tasks_mod():
    return _load("grimnir_tasks", "scripts/tasks.py")


@pytest.fixture(scope="session")
def playbook_mod():
    return _load("grimnir_playbook", "scripts/playbook.py")


@pytest.fixture(scope="session")
def executor_mod():
    return _load("grimnir_executor", "scripts/executor.py")


@pytest.fixture(scope="session")
def lane_runner_mod():
    return _load("grimnir_lane_runner", "scripts/lane-runner.py")


@pytest.fixture(scope="session")
def scope_mod():
    return _load("grimnir_scope", "scripts/scope.py")


@pytest.fixture(scope="session")
def lane_synth_mod():
    return _load("grimnir_lane_synth", "scripts/lane-synth.py")


@pytest.fixture(scope="session")
def creds_normalize_mod():
    return _load("grimnir_creds_normalize", "scripts/creds-normalize.py")


@pytest.fixture(scope="session")
def race_confirm_mod():
    return _load("grimnir_race_confirm", "scripts/confirm/race-confirm.py")


@pytest.fixture(scope="session")
def infoleak_confirm_mod():
    return _load("grimnir_infoleak_confirm", "scripts/confirm/infoleak-confirm.py")


@pytest.fixture(scope="session")
def ssrf_confirm_mod():
    return _load("grimnir_ssrf_confirm", "scripts/confirm/ssrf-confirm.py")


@pytest.fixture(scope="session")
def jwt_confirm_mod():
    return _load("grimnir_jwt_confirm", "scripts/confirm/jwt-confirm.py")


@pytest.fixture(scope="session")
def bopla_confirm_mod():
    return _load("grimnir_bopla_confirm", "scripts/confirm/bopla-confirm.py")


@pytest.fixture(scope="session")
def ssti_confirm_mod():
    return _load("grimnir_ssti_confirm", "scripts/confirm/ssti-confirm.py")


@pytest.fixture
def authn_confirm_mod():
    return _load("grimnir_authn_confirm", "scripts/confirm/authn-confirm.py")


@pytest.fixture(scope="session")
def tier_confirm_mod():
    return _load("grimnir_tier_confirm", "scripts/confirm/tier-confirm.py")


@pytest.fixture(scope="session")
def sqli_confirm_mod():
    return _load("grimnir_sqli_confirm", "scripts/confirm/sqli-confirm.py")


@pytest.fixture(scope="session")
def xss_confirm_mod():
    return _load("grimnir_xss_confirm", "scripts/confirm/xss-confirm.py")


@pytest.fixture(scope="session")
def llm_confirm_mod():
    return _load("grimnir_llm_confirm", "scripts/confirm/llm-confirm.py")


@pytest.fixture(scope="session")
def route_classify_mod():
    return _load("grimnir_route_classify", "scripts/route-classify.py")


@pytest.fixture(scope="session")
def ai_log_mod():
    return _load("grimnir_ai_log", "scripts/ai_log.py")


@pytest.fixture(scope="session")
def attack_plan_mod():
    return _load("grimnir_attack_plan", "scripts/attack-plan.py")


@pytest.fixture(scope="session")
def corpus_candidates_mod():
    return _load("grimnir_corpus_candidates", "scripts/corpus_candidates.py")


@pytest.fixture(scope="session")
def authed_crawl_mod():
    return _load("grimnir_authed_crawl", "scripts/authed-crawl.py")


@pytest.fixture(scope="session")
def writeup_intel_mod():
    return _load("grimnir_writeup_intel", "scripts/writeup_intel.py")


@pytest.fixture(scope="session")
def openapi_assetmap_mod():
    return _load("grimnir_openapi_to_assetmap", "scripts/openapi-to-assetmap.py")


@pytest.fixture(scope="session")
def onboard_model_mod():
    return _load("grimnir_onboard_model", "scripts/onboard-model.py")


@pytest.fixture(scope="session")
def graphql_probe_mod():
    return _load("grimnir_graphql_probe", "specter/scripts/graphql-probe.py")


@pytest.fixture(autouse=True)
def _isolate_activity_rollup(monkeypatch, tmp_path):
    """Anything that fires a lane or creates a finding appends to the host-global activity
    rollup. Keep the suite's synthetic events out of the operator's real one."""
    monkeypatch.setenv("GRIMNIR_ACTIVITY_ROLLUP", str(tmp_path / "activity-rollup.jsonl"))


@pytest.fixture(autouse=True)
def _isolate_executor_runs(monkeypatch, tmp_path):
    """A live executor walk records each parked run under $GRIMNIR_HOME/executor-runs. Keep the
    suite's synthetic runs out of the operator's real records (the stale-gate sweep acts on them)."""
    monkeypatch.setenv("GRIMNIR_EXECUTOR_RUNS_DIR", str(tmp_path / "executor-runs"))


@pytest.fixture(autouse=True)
def _isolate_daemon(monkeypatch):
    """finding.sh, validate-finding.sh and the lane runner report events through event-emitter.sh,
    which falls back to the daemon named in ~/.grimnir/config.json. Keep the suite's synthetic
    findings off the operator's live daemon."""
    monkeypatch.setenv("GRIMNIR_DAEMON", "off")


@pytest.fixture(scope="session")
def activity_mod():
    return _load("grimnir_activity", "scripts/activity.py")


@pytest.fixture(autouse=True)
def _isolate_egress_proxy(monkeypatch):
    """A proxy exported for a live engagement (GRIMNIR_PROXY) would route the suite's loopback stub
    servers through it, or fail closed against it. Unit tests run direct unless they set it."""
    monkeypatch.delenv("GRIMNIR_PROXY", raising=False)


@pytest.fixture(autouse=True)
def _isolate_operator_config(monkeypatch):
    """Unit tests must be hermetic. executor.load_config() with no arg reads the operator's real
    ~/.grimnir/executor.json — which, under the prior-engagements-only first-run profile, carries
    a targeting.programs allowlist that would reject the tests' synthetic programs. Point the
    override env at a path that cannot exist so load_config() always returns pure DEFAULT_CONFIG.
    Harmless for the non-executor suites (nothing else reads this var)."""
    monkeypatch.setenv("GRIMNIR_EXECUTOR_CONFIG", str(REPO / "tests" / "_nonexistent_executor_config.json"))


@pytest.fixture(scope="session")
def state_mod():
    return _load("grimnir_finding_state", "scripts/finding_state.py")


@pytest.fixture(scope="session")
def fresh_mod():
    return _load("grimnir_fresh_eyes", "scripts/fresh-eyes.py")


@pytest.fixture(scope="session")
def repo_root():
    return REPO


@pytest.fixture(scope="session")
def roe_mod():
    return _load("grimnir_roe", "scripts/roe.py")


@pytest.fixture(scope="session")
def session_mod():
    return _load("grimnir_session", "scripts/session.py")


@pytest.fixture(scope="session")
def writeup_gaps_mod():
    return _load("grimnir_writeup_gaps", "scripts/writeup_gaps.py")


@pytest.fixture(scope="session")
def login_mod():
    return _load("grimnir_login", "scripts/login.py")


@pytest.fixture(scope="session")
def caido_export_mod():
    return _load("grimnir_caido_export", "scripts/caido-export.py")


@pytest.fixture(scope="session")
def chain_mod():
    return _load("grimnir_chain", "scripts/chain.py")
