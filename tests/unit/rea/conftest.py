from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def rea_trust_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key_path = tmp_path / "trusted-keys.json"
    approver_path = tmp_path / "trusted-approvers.json"
    key_path.write_text(
        json.dumps(
            {
                "keys": {
                    "test-key-01": {
                        "public_key_pem": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                        "status": "ACTIVE",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    approver_path.write_text(
        json.dumps(
            {
                "approvers": {
                    "approver-1": {
                        "role": "HUMAN_APPROVER",
                        "status": "ACTIVE",
                        "allowed_actions": ["APPROVE_STAGE_05B", "RUN_REA_EXECUTION"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASTRA_REA_TEST_CLOCK", "1")
    monkeypatch.setenv("ASTRA_REA_TRUSTED_KEYS_PATH", str(key_path))
    monkeypatch.setenv("ASTRA_REA_APPROVER_REGISTRY_PATH", str(approver_path))
