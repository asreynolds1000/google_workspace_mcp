"""
Test that the ruff.yml GitHub Actions workflow does NOT check out
attacker-controlled code from fork PRs (CWE-77).

The vulnerability: the workflow uses pull_request trigger with
  repository: ${{ github.event.pull_request.head.repo.full_name }}
which checks out the fork's code directly. An attacker can poison
pyproject.toml or inject malicious ruff plugins to achieve code execution
with the workflow's contents:write GITHUB_TOKEN.

The fix: remove the explicit repository/ref override so `actions/checkout`
uses the default merge commit ref (github.sha) for pull_request events,
and avoid project-aware installers (`uv sync`, `pip install .`) on the
fork-facing validation job so attacker-controlled build hooks cannot run.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Tuple

import yaml

# Resolve the repo root (one level up from tests/)
REPO_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW_PATH: str = os.path.join(REPO_ROOT, ".github", "workflows", "ruff.yml")

# Commands that resolve and execute the project's own build backend /
# pyproject.toml hooks. These must NOT run on untrusted fork PR code.
PROJECT_INSTALL_COMMANDS: Tuple[str, ...] = (
    "uv sync",
    "uv pip install -e",
    "uv pip install .",
    "pip install -e",
    "pip install .",
    "poetry install",
)


def load_workflow(path: str) -> Tuple[Dict[str, Any], str]:
    """Load a workflow file and return (parsed_yaml, raw_text)."""
    with open(path, "r") as f:
        raw: str = f.read()
    parsed: Dict[str, Any] = yaml.safe_load(raw)
    return parsed, raw


def _job_has_write_permission(job: Dict[str, Any]) -> bool:
    """Return True if a job grants any write-scoped permission."""
    perms: Any = job.get("permissions", {})
    if isinstance(perms, str):
        return perms == "write-all"
    if isinstance(perms, dict):
        return any(v == "write" for v in perms.values())
    return False


def _workflow_has_write_permission(wf: Dict[str, Any]) -> bool:
    """Return True if the top-level workflow grants any write-scoped permission."""
    perms: Any = wf.get("permissions", {})
    if isinstance(perms, str):
        return perms == "write-all"
    if isinstance(perms, dict):
        return any(v == "write" for v in perms.values())
    return False


def test_no_fork_repo_checkout() -> None:
    """Checkout step must NOT reference github.event.pull_request.head.repo.full_name
    as the repository parameter, which would check out attacker-controlled fork code."""
    wf, _raw = load_workflow(WORKFLOW_PATH)

    jobs: Dict[str, Any] = wf.get("jobs", {})
    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses: str = step.get("uses", "")
            if "actions/checkout" in uses:
                with_params: Dict[str, Any] = step.get("with", {})
                repo_param: str = str(with_params.get("repository", ""))

                # Must NOT reference the fork's repo
                assert "pull_request.head.repo" not in repo_param, (
                    f"Job \'{job_name}\' checkout uses fork repository: {repo_param}. "
                    "This allows attacker-controlled code execution."
                )


def test_uv_sync_not_on_fork_prs() -> None:
    """Any project-aware install step (uv sync, pip install ., etc.) must
    either be absent from fork-reachable jobs or guarded by a fork check on
    the step itself. We assert directly on the install step rather than on
    the checkout to catch unguarded installs even when the checkout looks
    safe."""
    wf, _raw = load_workflow(WORKFLOW_PATH)

    jobs: Dict[str, Any] = wf.get("jobs", {})
    for job_name, job in jobs.items():
        job_if: str = str(job.get("if", ""))
        job_is_fork_guarded: bool = (
            "head.repo.full_name == github.repository" in job_if
            or "head.repo.full_name ==" in job_if
        )

        steps = job.get("steps", [])
        for step in steps:
            run_cmd: str = str(step.get("run", ""))
            if not any(cmd in run_cmd for cmd in PROJECT_INSTALL_COMMANDS):
                continue

            step_if: str = str(step.get("if", ""))
            step_is_fork_guarded: bool = (
                "head.repo.full_name == github.repository" in step_if
                or "head.repo.full_name ==" in step_if
            )

            assert job_is_fork_guarded or step_is_fork_guarded, (
                f"Job \'{job_name}\' runs a project-aware install "
                f"({run_cmd.strip().splitlines()[0]!r}) without a fork guard "
                "on either the job or the step. Attacker-controlled "
                "pyproject.toml/build hooks could execute on fork PRs."
            )


def test_no_write_permissions_or_fork_guarded() -> None:
    """If any job (or the workflow) grants write permissions, that job must
    not execute fork code: checkout must not point at the fork repo and the
    job must be guarded by a same-repo `if` condition."""
    wf, _raw = load_workflow(WORKFLOW_PATH)

    workflow_has_write: bool = _workflow_has_write_permission(wf)
    jobs: Dict[str, Any] = wf.get("jobs", {})

    for job_name, job in jobs.items():
        job_has_write: bool = _job_has_write_permission(job)
        has_write: bool = workflow_has_write or job_has_write
        if not has_write:
            continue

        job_if: str = str(job.get("if", ""))
        job_is_fork_guarded: bool = (
            "head.repo.full_name == github.repository" in job_if
            or "head.repo.full_name ==" in job_if
        )

        steps = job.get("steps", [])
        for step in steps:
            uses: str = step.get("uses", "")
            if "actions/checkout" in uses:
                with_params: Dict[str, Any] = step.get("with", {})
                repo_param: str = str(with_params.get("repository", ""))
                assert "pull_request.head.repo" not in repo_param, (
                    f"Job \'{job_name}\' has write permissions AND checks out fork code. "
                    "This is a critical security issue (CWE-77)."
                )

        assert job_is_fork_guarded, (
            f"Job \'{job_name}\' has write permissions but lacks a same-repo "
            "`if` guard. Add `if: github.event.pull_request.head.repo.full_name "
            "== github.repository` (or equivalent) to prevent fork PRs from "
            "running with elevated permissions."
        )


if __name__ == "__main__":
    tests = [
        test_no_fork_repo_checkout,
        test_uv_sync_not_on_fork_prs,
        test_no_write_permissions_or_fork_guarded,
    ]

    failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS: {test.__name__}")
        except AssertionError as e:
            print(f"  FAIL: {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {test.__name__}: {e}")
            failed += 1

    if failed:
        print(f"\n{failed} test(s) failed")
        sys.exit(1)
    else:
        print("\nAll tests passed")
        sys.exit(0)
