import os
import subprocess
import textwrap
from pathlib import Path

import pytest


def _baseline_scope(base_ref: str, ref_name: str) -> str:
    """Mirror GitHub's `base_ref || ref_name` expression for contract cases."""
    return base_ref or ref_name


@pytest.mark.parametrize(
    ("base_ref", "ref_name", "expected"),
    [
        ("", "main", "main"),
        ("main", "42/merge", "main"),
        ("develop", "123/merge", "develop"),
    ],
)
def test_action_baseline_scope_uses_target_branch(
    base_ref: str, ref_name: str, expected: str
) -> None:
    assert _baseline_scope(base_ref, ref_name) == expected


def test_pull_requests_restore_but_never_save_trusted_baselines() -> None:
    action = (Path(__file__).parents[1] / "action.yml").read_text(encoding="utf-8")

    scope_expression = "${{ github.base_ref || github.ref_name }}"
    assert action.count(scope_expression) == 2
    assert "github.event_name == 'push' || github.event_name == 'workflow_dispatch'" in action
    assert '"$GITHUB_EVENT_NAME" == "pull_request_target"' in action


@pytest.mark.parametrize(
    "event", ["pull_request", "pull_request_target", "push", "workflow_dispatch"]
)
def test_real_action_script_blocks_pr_approval_before_install(event: str) -> None:
    action = (Path(__file__).parents[1] / "action.yml").read_text(encoding="utf-8")
    script = textwrap.dedent(action.split("      run: |\n", 1)[1].split("    - name:", 1)[0])
    # Intercept Python before package installation or target execution. This runs
    # the actual shipped guard, not a Python reimplementation of its behavior.
    script = 'python() { echo "reached-install"; return 87; }\n' + script
    result = subprocess.run(
        ["bash", "-e", "-c", script],
        env={
            **os.environ,
            "GITHUB_EVENT_NAME": event,
            "INPUT_APPROVE_BASELINE_FINGERPRINT": "a" * 64,
            "INPUT_APPROVE_BASELINE": "false",
            "INPUT_TRANSPORT": "http",
        },
        text=True,
        capture_output=True,
        timeout=5,
    )
    if event.startswith("pull_request"):
        assert result.returncode == 2
        assert "unavailable in pull request" in result.stdout
        assert "reached-install" not in result.stdout
    else:
        assert result.returncode == 87
        assert "reached-install" in result.stdout
