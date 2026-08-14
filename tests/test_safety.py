from mcpsentinel.safety import sanitize_text, sanitize_url


def test_uri_sanitizer_redacts_generic_query_path_and_encoded_secret_values() -> None:
    openai_key = "sk-proj-abcdefghijklmnop"
    nested_token = "nested-secret"
    value = (
        "https://example.com/mcp/"
        f"{openai_key}?value={openai_key}&api%5Fkey=primary-secret&"
        f"redirect=https%3A%2F%2Finner.example%2Fmcp%3Ftoken%3D{nested_token}"
    )

    redacted = sanitize_url(value)

    assert openai_key not in redacted
    assert "primary-secret" not in redacted
    assert nested_token not in redacted
    assert "api%5Fkey=[REDACTED]" in redacted
    assert "[REDACTED_OPENAI_KEY]" in redacted


def test_text_sanitizer_strips_credentials_from_non_http_resource_uris() -> None:
    value = "Resource: postgresql://alice:database-password@db.internal/customer-data"

    redacted = sanitize_text(value)

    assert "alice" not in redacted
    assert "database-password" not in redacted
    assert "postgresql://db.internal/customer-data" in redacted
