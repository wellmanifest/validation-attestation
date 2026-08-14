from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "attestation_check", ROOT / "src" / "attestation_check.py"
)
assert SPEC and SPEC.loader
attestation_check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = attestation_check
SPEC.loader.exec_module(attestation_check)


class AttestationConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.valid_path = ROOT / "examples" / "valid" / "subactor-pr-attestation.json"
        cls.valid = json.loads(cls.valid_path.read_text(encoding="utf-8"))
        cls.profile = json.loads(
            (ROOT / "profiles" / "subactor-semcod.profile.json").read_text(encoding="utf-8")
        )

    def codes(self, document: dict, **kwargs: object) -> set[str]:
        return {
            finding.code for finding in attestation_check.validate_document(document, **kwargs)
        }

    def test_valid_attestation_and_profile_pass(self) -> None:
        self.assertEqual(set(), self.codes(self.valid))
        self.assertEqual(set(), self.codes(self.profile))

    def test_invalid_fixtures_emit_declared_codes(self) -> None:
        for path in sorted((ROOT / "examples" / "invalid").glob("*.json")):
            case = json.loads(path.read_text(encoding="utf-8"))
            observed = {finding.code for finding in attestation_check.load_and_validate(path)}
            self.assertLessEqual(set(case["expectedCodes"]), observed, path.name)

    def test_unknown_root_and_nested_fields_fail_closed(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["trustMe"] = True
        self.assertIn(attestation_check.SYNTAX, self.codes(mutation))
        mutation = copy.deepcopy(self.valid)
        mutation["subject"]["branch"] = "main"
        self.assertIn(attestation_check.SYNTAX, self.codes(mutation))

    def test_validator_cannot_be_implementer_or_publisher(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["issuer"]["principal"] = mutation["subject"]["implementer"]
        self.assertIn(attestation_check.INDEPENDENCE, self.codes(mutation))
        mutation = copy.deepcopy(self.valid)
        mutation["issuer"]["principal"] = mutation["subject"]["publisher"]
        self.assertIn(attestation_check.INDEPENDENCE, self.codes(mutation))

    def test_protected_verifier_must_be_independent(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["verification"]["verifier"] = mutation["issuer"]["principal"]
        self.assertIn(attestation_check.INDEPENDENCE, self.codes(mutation))

    def test_approved_decision_requires_all_checks_successful(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["checks"][0]["conclusion"] = "skipped"
        self.assertIn(attestation_check.DECISION, self.codes(mutation))

    def test_exact_head_and_base_are_runtime_bound(self) -> None:
        expected = {"headSha": "f" * 40, "baseSha": self.valid["subject"]["baseSha"]}
        self.assertIn(attestation_check.SUBJECT, self.codes(self.valid, expected=expected))

    def test_policy_profile_and_grant_are_runtime_bound(self) -> None:
        expected = {"policyDigest": "sha256:" + "f" * 64}
        self.assertIn(attestation_check.SUBJECT, self.codes(self.valid, expected=expected))

    def test_expired_attestation_is_rejected(self) -> None:
        at = datetime.fromisoformat("2026-08-14T14:00:00+00:00")
        self.assertIn(attestation_check.TIME, self.codes(self.valid, at=at))

    def test_nonce_replay_is_rejected(self) -> None:
        nonce = self.valid["antiReplay"]["nonce"]
        self.assertIn(
            attestation_check.REPLAY,
            self.codes(self.valid, consumed_nonces={nonce}),
        )

    def test_signature_key_must_match_allowlisted_issuer_key(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["signature"]["keyId"] = "sigstore://attacker/key"
        self.assertIn(attestation_check.SIGNATURE, self.codes(mutation))

    def test_model_advice_cannot_be_promoted_to_decision(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["modelAdvice"]["advisory"] = False
        self.assertIn(attestation_check.DECISION, self.codes(mutation))

    def test_secret_bearing_fields_are_rejected(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["signature"]["privateKey"] = "Bearer example"
        codes = self.codes(mutation)
        self.assertIn(attestation_check.SECRET, codes)
        self.assertIn(attestation_check.SYNTAX, codes)

    def test_profile_enforces_stage_modes_and_principal_separation(self) -> None:
        mutation = copy.deepcopy(self.profile)
        publish = next(item for item in mutation["bindings"] if item["stage"] == "publish")
        attest = next(item for item in mutation["bindings"] if item["stage"] == "attest")
        publish["principal"] = attest["principal"]
        self.assertIn(attestation_check.PROFILE, self.codes(mutation))

    def test_schema_is_closed_draft_2020_12(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "validation-attestation.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
        for name in (
            "attestation", "profile", "principal", "issuer", "subject", "check",
            "decision", "modelAdvice", "validity", "antiReplay", "signature",
            "verification", "binding",
        ):
            self.assertFalse(schema["$defs"][name]["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
