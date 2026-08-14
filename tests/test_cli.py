from __future__ import annotations

from importlib.metadata import version

from mcpsentinel import __version__
from mcpsentinel.cli import main


def test_first_run_displays_safe_onboarding(capsys) -> None:
    assert main([]) == 0

    output = capsys.readouterr().out
    assert "MCPSENTINEL" in output
    assert "Read-only by default" in output
    assert f"Welcome to MCPSentinel {__version__}" in output
    assert "read-only" in output
    assert "mcpsentinel scan http://localhost:8000/mcp" in output
    assert "never commit API keys" in output


def test_onboarding_can_force_colored_terminal_ui(capsys) -> None:
    assert main(["--color", "always"]) == 0

    output = capsys.readouterr().out
    assert "\x1b[" in output
    assert "Your first three steps" in output
    assert "Copy this to begin" in output
    assert "When you are ready for CI" in output
    assert "mcpsentinel scan http://localhost:8000/mcp" in output


def test_onboard_tailors_a_stdio_command_without_scanning(capsys) -> None:
    assert (
        main(
            ["onboard", "--target", "python -m example_mcp_server", "--transport", "stdio"]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "mcpsentinel scan 'python -m example_mcp_server' --transport stdio" in output


def test_init_alias_and_version_are_available(capsys) -> None:
    assert main(["init"]) == 0
    assert f"Welcome to MCPSentinel {__version__}" in capsys.readouterr().out

    try:
        main(["--version"])
    except SystemExit as error:
        assert error.code == 0
    else:
        raise AssertionError("--version must exit after rendering its version")
    assert capsys.readouterr().out == f"mcpsentinel {__version__}\n"


def test_runtime_version_matches_installed_distribution() -> None:
    assert __version__ == version("mcp-guardian-scan")


def test_onboard_detects_but_never_echoes_an_openai_key(capsys, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-secret")

    assert main(["onboard"]) == 0

    output = capsys.readouterr().out
    assert "OPENAI_API_KEY is detected" in output
    assert "test-secret" not in output
