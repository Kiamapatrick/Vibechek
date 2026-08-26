import json
from unittest.mock import MagicMock, patch

import httpx
import pytest
from groq import APIConnectionError, APIError, APITimeoutError, RateLimitError

import vibeshield.triage.config as config_module
from vibeshield.models.finding import Evidence, Finding, SeverityLevel
from vibeshield.triage.llm.client import GroqClient, get_client
from vibeshield.triage.models import ContextSnippet

_FAKE_REQUEST = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")


def _fake_rate_limit_error() -> RateLimitError:
    response = httpx.Response(429, request=_FAKE_REQUEST)
    return RateLimitError("rate limited", response=response, body=None)


def _fake_timeout_error() -> APITimeoutError:
    return APITimeoutError(request=_FAKE_REQUEST)


def _fake_connection_error() -> APIConnectionError:
    return APIConnectionError(request=_FAKE_REQUEST)


def _fake_bad_request_error() -> APIError:
    return APIError("bad request", request=_FAKE_REQUEST, body=None)


@pytest.fixture(autouse=True)
def _reset_settings_singleton(monkeypatch):
    """get_settings() caches a module-level singleton, so each test needs a
    clean slate + a valid GROQ_API_KEY in the environment or construction
    fails before the test's own api_key argument is ever consulted."""
    monkeypatch.setenv("GROQ_API_KEY", "test-env-key")
    config_module._settings = None
    yield
    config_module._settings = None


def _make_finding(**overrides) -> Finding:
    defaults = {
        "check": "exposed_secrets",
        "title": "Exposed AWS Access Key",
        "severity": SeverityLevel.CRITICAL,
        "score": 20,
        "impact": 5,
        "likelihood": 4,
        "wstg_id": "WSTG-INFO-02",
        "attck_ids": ["T1552.001"],
        "evidence": Evidence(url="http://localhost:8080", snippet='const apiKey = "AKIA..."'),
        "confidence": 0.9,
        "remediation": "Rotate key",
        "references": [],
    }
    defaults.update(overrides)
    return Finding(**defaults)


def _mock_response(content: str | None):
    response = MagicMock()
    response.choices = [MagicMock(message=MagicMock(content=content))]
    return response


VALID_JSON = json.dumps(
    {
        "explanation": "An AWS key was found in your client-side code.",
        "exploitability": 5,
        "fix": "Rotate the key in AWS IAM and move it server-side.",
        "revised_priority": 5,
    }
)


class TestGroqClientGenerate:
    def test_generate_happy_path_returns_triage_result(self):
        client = GroqClient(api_key="fake-key")
        with patch.object(client._client.chat.completions, "create", return_value=_mock_response(VALID_JSON)):
            result = client.generate(_make_finding(), context=[])
        assert result.source == "llm"
        assert result.prompt_version == "v1"
        assert result.exploitability == 5
        assert result.revised_priority == 5
        assert "Rotate" in result.fix

    def test_generate_sends_correct_model_and_params(self):
        client = GroqClient(api_key="fake-key", model="custom-model", temperature=0.5, max_tokens=999)
        with patch.object(client._client.chat.completions, "create", return_value=_mock_response(VALID_JSON)) as mock_create:
            client.generate(_make_finding(), context=[])
        kwargs = mock_create.call_args.kwargs
        assert kwargs["model"] == "custom-model"
        assert kwargs["temperature"] == 0.5
        assert kwargs["max_tokens"] == 999
        assert kwargs["response_format"] == {"type": "json_object"}
        assert kwargs["messages"][0]["role"] == "system"
        assert kwargs["messages"][1]["role"] == "user"

    def test_generate_includes_context_snippets_in_prompt(self):
        client = GroqClient(api_key="fake-key")
        snippet = ContextSnippet(topic="exposed_secrets", content="Rotate keys immediately.", source_file="exposed_secrets.md")
        with patch.object(client._client.chat.completions, "create", return_value=_mock_response(VALID_JSON)) as mock_create:
            client.generate(_make_finding(), context=[snippet])
        user_msg = mock_create.call_args.kwargs["messages"][1]["content"]
        assert "exposed_secrets" in user_msg
        assert "Rotate keys immediately." in user_msg

    def test_generate_no_context_uses_placeholder(self):
        client = GroqClient(api_key="fake-key")
        with patch.object(client._client.chat.completions, "create", return_value=_mock_response(VALID_JSON)) as mock_create:
            client.generate(_make_finding(), context=[])
        user_msg = mock_create.call_args.kwargs["messages"][1]["content"]
        assert "No relevant context retrieved" in user_msg

    def test_generate_rejects_unknown_prompt_version(self):
        client = GroqClient(api_key="fake-key")
        with pytest.raises(ValueError, match="Unknown prompt version"):
            client.generate(_make_finding(), context=[], prompt_version="v2")

    def test_generate_raises_on_empty_content(self):
        client = GroqClient(api_key="fake-key")
        with (
            patch.object(client._client.chat.completions, "create", return_value=_mock_response(None)),
            pytest.raises(ValueError, match="Empty response from Groq"),
        ):
            client.generate(_make_finding(), context=[])

    def test_generate_raises_on_malformed_json(self):
        client = GroqClient(api_key="fake-key")
        with (
            patch.object(client._client.chat.completions, "create", return_value=_mock_response("not json")),
            pytest.raises(json.JSONDecodeError),
        ):
            client.generate(_make_finding(), context=[])

    @pytest.mark.parametrize("missing_field", ["explanation", "exploitability", "fix", "revised_priority"])
    def test_generate_raises_on_missing_field(self, missing_field):
        data = json.loads(VALID_JSON)
        del data[missing_field]
        client = GroqClient(api_key="fake-key")
        with (
            patch.object(client._client.chat.completions, "create", return_value=_mock_response(json.dumps(data))),
            pytest.raises(ValueError, match=f"Missing required field.*{missing_field}"),
        ):
            client.generate(_make_finding(), context=[])

    @pytest.mark.parametrize("bad_value", [0, 6, -1, 100])
    def test_generate_raises_on_out_of_range_exploitability(self, bad_value):
        data = json.loads(VALID_JSON)
        data["exploitability"] = bad_value
        client = GroqClient(api_key="fake-key")
        with (
            patch.object(client._client.chat.completions, "create", return_value=_mock_response(json.dumps(data))),
            pytest.raises(ValueError, match="exploitability must be between 1 and 5"),
        ):
            client.generate(_make_finding(), context=[])

    def test_generate_raises_on_non_numeric_exploitability(self):
        data = json.loads(VALID_JSON)
        data["exploitability"] = "high"
        client = GroqClient(api_key="fake-key")
        with (
            patch.object(client._client.chat.completions, "create", return_value=_mock_response(json.dumps(data))),
            pytest.raises(ValueError),
        ):
            client.generate(_make_finding(), context=[])


class TestGroqClientConstruction:
    def test_explicit_api_key_works_without_env_var(self, monkeypatch):
        """Explicit api_key should be sufficient on its own — no GROQ_API_KEY
        needed in the environment/.env."""
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        config_module._settings = None
        client = GroqClient(api_key="fake-key")
        assert client is not None

    def test_no_api_key_anywhere_raises_clear_error(self, monkeypatch):
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        config_module._settings = None
        with pytest.raises(ValueError, match="No Groq API key provided"):
            GroqClient()

    def test_defaults_come_from_settings_when_not_overridden(self):
        client = GroqClient()
        assert client._model == "openai/gpt-oss-20b"
        assert client._temperature == 0.1
        assert client._max_tokens == 2048
        assert client._max_retries == 3
        assert client._retry_base_delay == 1.0

    def test_explicit_overrides_win_over_settings(self):
        client = GroqClient(
            model="other-model", temperature=0.9, max_tokens=100, max_retries=5, retry_base_delay=0.01
        )
        assert client._model == "other-model"
        assert client._temperature == 0.9
        assert client._max_tokens == 100
        assert client._max_retries == 5
        assert client._retry_base_delay == 0.01

    def test_explicit_api_key_and_other_settings_still_come_from_env(self, monkeypatch):
        """api_key can be passed explicitly while model/temperature/etc still
        fall back to settings loaded from the environment/.env — the two are
        independent."""
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        config_module._settings = None
        client = GroqClient(api_key="fake-key")
        assert client._model == "openai/gpt-oss-20b"  # from settings default


class TestGroqClientRetry:
    """Retries only apply to transient errors (rate limit, timeout, connection).
    Uses a near-zero base delay so these tests run fast."""

    def test_retries_on_rate_limit_then_succeeds(self):
        client = GroqClient(api_key="fake-key", retry_base_delay=0.001)
        side_effects = [_fake_rate_limit_error(), _mock_response(VALID_JSON)]
        with patch.object(client._client.chat.completions, "create", side_effect=side_effects) as mock_create:
            result = client.generate(_make_finding(), context=[])
        assert mock_create.call_count == 2
        assert result.exploitability == 5

    def test_retries_on_timeout_then_succeeds(self):
        client = GroqClient(api_key="fake-key", retry_base_delay=0.001)
        side_effects = [_fake_timeout_error(), _mock_response(VALID_JSON)]
        with patch.object(client._client.chat.completions, "create", side_effect=side_effects) as mock_create:
            client.generate(_make_finding(), context=[])
        assert mock_create.call_count == 2

    def test_retries_on_connection_error_then_succeeds(self):
        client = GroqClient(api_key="fake-key", retry_base_delay=0.001)
        side_effects = [_fake_connection_error(), _mock_response(VALID_JSON)]
        with patch.object(client._client.chat.completions, "create", side_effect=side_effects) as mock_create:
            client.generate(_make_finding(), context=[])
        assert mock_create.call_count == 2

    def test_gives_up_after_max_retries(self):
        client = GroqClient(api_key="fake-key", max_retries=2, retry_base_delay=0.001)
        with (
            patch.object(client._client.chat.completions, "create", side_effect=_fake_rate_limit_error()) as mock_create,
            pytest.raises(RateLimitError),
        ):
            client.generate(_make_finding(), context=[])
        assert mock_create.call_count == 3  # 1 initial attempt + 2 retries

    def test_does_not_retry_on_non_retryable_api_error(self):
        """A generic APIError (e.g. bad request/auth failure) should fail
        fast, not burn through retry attempts."""
        client = GroqClient(api_key="fake-key", max_retries=3, retry_base_delay=0.001)
        with (
            patch.object(client._client.chat.completions, "create", side_effect=_fake_bad_request_error()) as mock_create,
            pytest.raises(APIError),
        ):
            client.generate(_make_finding(), context=[])
        assert mock_create.call_count == 1

    def test_zero_max_retries_means_single_attempt(self):
        client = GroqClient(api_key="fake-key", max_retries=0, retry_base_delay=0.001)
        with (
            patch.object(client._client.chat.completions, "create", side_effect=_fake_rate_limit_error()) as mock_create,
            pytest.raises(RateLimitError),
        ):
            client.generate(_make_finding(), context=[])
        assert mock_create.call_count == 1


class TestGetClient:
    def test_get_client_is_singleton(self):
        c1 = get_client()
        c2 = get_client()
        assert c1 is c2
