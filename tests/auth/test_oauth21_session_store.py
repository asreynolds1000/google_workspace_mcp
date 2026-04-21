from auth.oauth21_session_store import OAuth21SessionStore


def test_oauth_state_persists_across_store_instances(tmp_path):
    state_file = tmp_path / "oauth_states.json"
    store_a = OAuth21SessionStore(oauth_state_file=str(state_file))
    store_b = OAuth21SessionStore(oauth_state_file=str(state_file))

    store_a.store_oauth_state(
        "shared-state",
        session_id="session-123",
        code_verifier="verifier-123",
    )

    state_info = store_b.validate_and_consume_oauth_state(
        "shared-state",
        session_id="session-123",
    )

    assert state_info["session_id"] == "session-123"
    assert state_info["code_verifier"] == "verifier-123"


def test_consume_latest_oauth_state_reads_from_shared_file(tmp_path):
    state_file = tmp_path / "oauth_states.json"
    store_a = OAuth21SessionStore(oauth_state_file=str(state_file))
    store_b = OAuth21SessionStore(oauth_state_file=str(state_file))

    store_a.store_oauth_state(
        "latest-state",
        session_id=None,
        code_verifier="latest-verifier",
    )

    state_info = store_b.consume_latest_oauth_state()

    assert state_info is not None
    assert state_info["code_verifier"] == "latest-verifier"
    assert store_a.consume_latest_oauth_state() is None


def test_consume_latest_oauth_state_filters_by_initiating_session_id(tmp_path):
    state_file = tmp_path / "oauth_states.json"
    store_a = OAuth21SessionStore(oauth_state_file=str(state_file))
    store_b = OAuth21SessionStore(oauth_state_file=str(state_file))

    store_a.store_oauth_state(
        "state-none",
        session_id=None,
        code_verifier="verifier-none",
    )
    store_a.store_oauth_state(
        "state-session-1",
        session_id="session-1",
        code_verifier="verifier-session-1",
    )

    state_info = store_b.consume_latest_oauth_state(initiating_session_id="session-1")

    assert state_info is not None
    assert state_info["session_id"] == "session-1"
    assert state_info["code_verifier"] == "verifier-session-1"

    remaining_state_info = store_a.consume_latest_oauth_state(
        initiating_session_id=None
    )
    assert remaining_state_info is not None
    assert remaining_state_info["session_id"] is None
    assert remaining_state_info["code_verifier"] == "verifier-none"


def test_deserialize_oauth_state_entry_normalizes_invalid_and_naive_timestamps(
    tmp_path,
):
    state_file = tmp_path / "oauth_states.json"
    store = OAuth21SessionStore(oauth_state_file=str(state_file))

    deserialized = store._deserialize_oauth_state_entry(
        {
            "created_at": "2026-04-21T12:00:00",
            "expires_at": "not-a-timestamp",
            "session_id": "session-123",
        }
    )

    assert deserialized["created_at"] is not None
    assert deserialized["created_at"].tzinfo is not None
    assert deserialized["expires_at"] is None
