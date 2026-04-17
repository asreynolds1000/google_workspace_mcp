"""
Account enumeration tools for the Google Workspace MCP server.

Exposes `list_configured_accounts` — a read-only tool that reports which Google
accounts currently have stored credentials in the configured credential store.
Useful for multi-account fan-out patterns in MCP clients: discover the account
list at runtime rather than hardcoding it.

This tool does NOT authenticate against any Google API and does NOT use
`@require_google_service`. It reads local credential metadata only.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from auth.credential_store import get_credential_store, LocalDirectoryCredentialStore
from core.server import server

logger = logging.getLogger(__name__)


def _credential_file_mtime_iso(
    store: LocalDirectoryCredentialStore, email: str
) -> str | None:
    """Return the credential file's mtime as an ISO-8601 UTC string, or None
    if the file doesn't exist or the store isn't a local-directory store.

    Side-effect-free: uses ``_resolve_credential_path`` (no ``os.makedirs``)
    with the same ``quote()`` + legacy-fallback lookup that
    ``_get_credential_path`` performs.
    """
    if not isinstance(store, LocalDirectoryCredentialStore):
        return None
    try:
        ext = store.FILE_EXTENSION
        safe_email = quote(email, safe="@._-")
        path = store._resolve_credential_path(f"{safe_email}{ext}")
        if not os.path.exists(path):
            legacy = store._legacy_safe_email(email)
            if legacy != safe_email:
                path = store._resolve_credential_path(f"{legacy}{ext}")
            if not os.path.exists(path):
                return None
        mtime = os.path.getmtime(path)
        return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
    except (OSError, ValueError) as e:
        logger.debug(f"Could not read mtime for {email}: {e}")
        return None


async def _list_configured_accounts_impl() -> dict[str, Any]:
    """Implementation of list_configured_accounts. Kept separate from the
    @server.tool-decorated wrapper so tests can call it directly without
    going through the MCP dispatch layer.

    Store operations are wrapped in asyncio.to_thread so synchronous
    filesystem I/O (os.listdir, open, os.path.getmtime inside the store)
    doesn't block the event loop — per the repo's coding guideline that
    blocking calls run in an executor.
    """
    store = get_credential_store()
    try:
        emails = await asyncio.to_thread(store.list_users)
    except (OSError, ValueError, NotImplementedError) as e:
        logger.error(f"Failed to list users from credential store: {e}")
        return {
            "accounts": [],
            "errors": [{"email": None, "error": type(e).__name__}],
            "count": 0,
            "store_type": type(store).__name__,
        }

    accounts: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for email in emails:
        try:
            creds = await asyncio.to_thread(store.get_credential, email)
            if creds is None:
                # get_credential returns None for any of: malformed JSON,
                # missing required fields, file deleted between list_users
                # and here, or permission error. Don't overclaim.
                errors.append(
                    {"email": email, "error": "credentials could not be loaded"}
                )
                continue

            expiry_iso: str | None = None
            if creds.expiry is not None:
                # google-auth stores naive datetimes; preserve that shape in the ISO
                # representation rather than silently attaching a tz.
                expiry_iso = creds.expiry.isoformat()

            last_refreshed = await asyncio.to_thread(
                _credential_file_mtime_iso, store, email
            )
            accounts.append(
                {
                    "email": email,
                    "scopes": list(creds.scopes) if creds.scopes else None,
                    "expiry": expiry_iso,
                    "last_refreshed": last_refreshed,
                    "has_refresh_token": bool(creds.refresh_token),
                }
            )
        except (OSError, ValueError, AttributeError) as e:
            # Realistic per-account failure modes: filesystem (OSError),
            # malformed credential data (ValueError), and malformed
            # Credentials objects (AttributeError on .expiry/.scopes/etc.
            # if a custom store returns something non-standard).
            logger.warning(f"Error loading credential metadata for {email}: {e}")
            errors.append({"email": email, "error": type(e).__name__})

    return {
        "accounts": accounts,
        "errors": errors,
        "count": len(accounts),
        "store_type": type(store).__name__,
    }


@server.tool()
async def list_configured_accounts() -> dict[str, Any]:
    """Lists Google accounts with stored credentials and their metadata (scopes, expiry, last-refreshed).

    Reads local credential-store state only; does NOT call any Google API and
    does NOT use `@require_google_service`. Intended as the discovery primitive
    for multi-account clients — call once, fan out across the returned emails
    instead of hardcoding an account list.

    Returns a dict:
        {
            "accounts": [
                {
                    "email": str,
                    "scopes": list[str] | None,
                    "expiry": str | None,          # ISO-8601, may be naive UTC
                    "last_refreshed": str | None,  # ISO-8601 UTC (file mtime)
                    "has_refresh_token": bool,
                },
                ...
            ],
            "errors": [{"email": str | None, "error": str}, ...],
            "count": int,
            "store_type": str,
        }

    Per-account load errors are captured in the `errors` array rather than
    raised, so partial credential-store corruption doesn't fail the whole call.

    Note on the `email` field: the values returned are filename-derived
    identifiers, not guaranteed-round-trippable RFC 5322 addresses.
    `LocalDirectoryCredentialStore.list_users()` derives them from credential
    filenames, which may be URL-encoded or legacy-sanitized. The store itself
    identifies users by this form, so downstream `store.get_credential(email)`
    calls using these values resolve correctly.
    """
    return await _list_configured_accounts_impl()
