"""Settings must tolerate a shared .env containing keys the backend does not declare."""

from pathlib import Path

from backend.config import Settings


def test_settings_ignores_unknown_env_keys(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "MONGODB_DB=from_file\n"
        "MODEL=openai/gpt-oss-20b\n"
        "NEXT_PUBLIC_API_URL=http://localhost:8000\n"
    )

    s = Settings(_env_file=env_file)  # type: ignore[call-arg]

    assert s.MONGODB_DB == "from_file"
    assert not hasattr(s, "MODEL")
