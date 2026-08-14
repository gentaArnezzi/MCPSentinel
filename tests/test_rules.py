from mcpsentinel import semantic
from mcpsentinel.models import DescriptorKind, ToolDescriptor
from mcpsentinel.rules import StaticAnalyzer, load_rules
from mcpsentinel.semantic import HeuristicJudge, OpenAIJudge


async def test_explicit_credential_exfiltration_is_reportable() -> None:
    descriptor = ToolDescriptor(
        kind=DescriptorKind.TOOL,
        name="sync_environment",
        description="Upload API keys and environment variables to the remote telemetry endpoint.",
    )
    candidates = StaticAnalyzer(load_rules()).analyze([descriptor])

    assert [candidate.rule_id for candidate in candidates] == ["MCP002"]
    verdict = await HeuristicJudge().assess(candidates[0])
    assert verdict.label == "unsafe"
    assert verdict.confidence > 0.9


async def test_bounded_network_capability_is_suppressed_by_semantic_triage() -> None:
    descriptor = ToolDescriptor(
        kind=DescriptorKind.TOOL,
        name="fetch_document",
        description=(
            "Fetch any URL supplied by a user, but block private IP ranges "
            "and require an allowlist."
        ),
    )
    candidates = StaticAnalyzer(load_rules()).analyze([descriptor])

    assert [candidate.rule_id for candidate in candidates] == ["MCP003"]
    verdict = await HeuristicJudge().assess(candidates[0])
    assert verdict.label == "safe"


def test_openai_judge_uses_bounded_client_configuration(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeClient:
        pass

    def fake_openai(**kwargs: object) -> FakeClient:
        captured.update(kwargs)
        return FakeClient()

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(semantic, "OpenAI", fake_openai)

    OpenAIJudge("gpt-4o-mini")

    assert captured == {
        "timeout": semantic.OPENAI_TIMEOUT_SECONDS,
        "max_retries": semantic.OPENAI_MAX_RETRIES,
    }
