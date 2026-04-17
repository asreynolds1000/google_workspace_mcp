"""Tests for the list_configured_accounts tool.

Verifies credential enumeration, per-account metadata surfacing, and that
per-account load failures become entries in the errors array rather than
raising.
"""

import json
import os
from datetime import datetime
from unittest.mock import patch

import pytest

from auth.credential_store import (
    LocalDirectoryCredentialStore,
    set_credential_store,
)


def _write_credential_file(
    base_dir: str,
    email: str,
    scopes: list[str] | None = None,
    with_refresh: bool = True,
    expiry: datetime | None = None,
) -> str:
    """Write a fake credential JSON directly to disk."""
    os.makedirs(base_dir, mode=0o700, exist_ok=True)
    data = {
        "token": f"tok-{email}",
        "refresh_token": f"rtok-{email}" if with_refresh else None,
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "cid",
        "client_secret": "csec",
        "scopes": scopes or ["https://www.googleapis.com/auth/gmail.readonly"],
        "expiry": expiry.isoformat() if expiry else None,
    }
    path = os.path.join(base_dir, f"{email}.json")
    with open(path, "w") as f:
        json.dump(data, f)
    os.chmod(path, 0o600)
    return path


@pytest.fixture
def fresh_store(tmp_path, monkeypatch):
    """Install a fresh LocalDirectoryCredentialStore rooted at tmp_path
    as the global credential store for the duration of one test, and
    restore whatever was there before on teardown."""
    import auth.credential_store as cs

    base = tmp_path / "creds"
    store = LocalDirectoryCredentialStore(base_dir=str(base))
    # Capture prior global so teardown doesn't leak a default-rooted store
    # pointing at the real ~/.google_workspace_mcp/credentials directory
    # (or at tmp_path, which pytest is about to delete).
    previous = cs._credential_store
    set_credential_store(store)
    # Also pin the env var in case anything re-initializes
    monkeypatch.setenv("WORKSPACE_MCP_CREDENTIALS_DIR", str(base))
    yield store
    # Restore the prior global. Using the private attribute here is the
    # cleanest way to return to "exactly the state before" — including
    # the None-sentinel case where no store was registered yet.
    cs._credential_store = previous


@pytest.mark.asyncio
async def test_empty_store_returns_zero_accounts(fresh_store):
    """No credential files on disk → zero accounts, zero errors."""
    from auth.account_tools import _list_configured_accounts_impl

    result = await _list_configured_accounts_impl()

    assert result["count"] == 0
    assert result["accounts"] == []
    assert result["errors"] == []
    assert result["store_type"] == "LocalDirectoryCredentialStore"


@pytest.mark.asyncio
async def test_two_accounts_enumerated(fresh_store):
    """Two valid credential files → both returned with metadata."""
    from auth.account_tools import _list_configured_accounts_impl

    _write_credential_file(
        str(fresh_store.base_dir),
        "a@example.com",
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )
    _write_credential_file(
        str(fresh_store.base_dir),
        "b@example.com",
        scopes=["https://www.googleapis.com/auth/calendar.readonly"],
        with_refresh=False,
    )

    result = await _list_configured_accounts_impl()

    assert result["count"] == 2
    emails = {a["email"] for a in result["accounts"]}
    assert emails == {"a@example.com", "b@example.com"}

    by_email = {a["email"]: a for a in result["accounts"]}
    assert by_email["a@example.com"]["has_refresh_token"] is True
    assert by_email["b@example.com"]["has_refresh_token"] is False
    assert by_email["a@example.com"]["scopes"] == [
        "https://www.googleapis.com/auth/gmail.readonly"
    ]
    # last_refreshed should be an ISO-8601 string for both
    for a in result["accounts"]:
        assert a["last_refreshed"] is not None
        datetime.fromisoformat(a["last_refreshed"])  # parses without error


@pytest.mark.asyncio
async def test_expiry_surfaced_when_present(fresh_store):
    """Expiry field round-trips when present."""
    from auth.account_tools import _list_configured_accounts_impl

    expiry = datetime(2026, 12, 31, 23, 59, 59)
    _write_credential_file(
        str(fresh_store.base_dir),
        "c@example.com",
        expiry=expiry,
    )

    result = await _list_configured_accounts_impl()

    assert result["count"] == 1
    assert result["accounts"][0]["expiry"] is not None
    # The credential store parses and re-emits via Credentials; exact string
    # may normalize, so parse both sides rather than compare literally.
    assert datetime.fromisoformat(result["accounts"][0]["expiry"]) == expiry


@pytest.mark.asyncio
async def test_corrupt_credential_becomes_error_not_exception(fresh_store):
    """A malformed credential file is captured in errors, doesn't raise,
    and doesn't prevent other accounts from listing."""
    from auth.account_tools import _list_configured_accounts_impl

    # Valid account
    _write_credential_file(str(fresh_store.base_dir), "good@example.com")
    # Corrupt JSON
    bad_path = os.path.join(str(fresh_store.base_dir), "bad@example.com.json")
    with open(bad_path, "w") as f:
        f.write("{this is not json")
    os.chmod(bad_path, 0o600)

    result = await _list_configured_accounts_impl()

    # Good account still listed
    assert result["count"] == 1
    assert result["accounts"][0]["email"] == "good@example.com"
    # Bad account captured as error — exactly once, and NOT also listed as
    # a valid account. Pin the failure-isolation contract: corrupt files
    # end up in errors only, never in accounts.
    error_emails = {e["email"] for e in result["errors"]}
    assert "bad@example.com" in error_emails
    assert len(result["errors"]) == 1
    assert all(a["email"] != "bad@example.com" for a in result["accounts"])


@pytest.mark.asyncio
async def test_non_credential_files_skipped(fresh_store):
    """Files without @ (e.g., oauth_states.json) are ignored by list_users."""
    from auth.account_tools import _list_configured_accounts_impl

    _write_credential_file(str(fresh_store.base_dir), "user@example.com")
    # Non-credential file the store is documented to skip
    with open(os.path.join(str(fresh_store.base_dir), "oauth_states.json"), "w") as f:
        json.dump({}, f)

    result = await _list_configured_accounts_impl()

    assert result["count"] == 1
    assert result["accounts"][0]["email"] == "user@example.com"


@pytest.mark.asyncio
async def test_store_list_users_failure_returns_error_record(fresh_store):
    """If the credential store itself raises on list_users, the tool
    returns an error record rather than propagating the exception."""
    from auth.account_tools import _list_configured_accounts_impl

    with patch.object(
        fresh_store, "list_users", side_effect=OSError("simulated FS failure")
    ):
        result = await _list_configured_accounts_impl()

    assert result["count"] == 0
    assert len(result["errors"]) == 1
    assert result["errors"][0]["email"] is None
    assert result["errors"][0]["error"] == "OSError"


@pytest.mark.asyncio
async def test_store_not_implemented_returns_error_record(fresh_store):
    """A store whose list_users raises NotImplementedError (e.g.,
    GCSCredentialStore) returns a clean error, not a crash."""
    from auth.account_tools import _list_configured_accounts_impl

    with patch.object(
        fresh_store,
        "list_users",
        side_effect=NotImplementedError("GCS does not support listing"),
    ):
        result = await _list_configured_accounts_impl()

    assert result["count"] == 0
    assert len(result["errors"]) == 1
    assert result["errors"][0]["error"] == "NotImplementedError"
