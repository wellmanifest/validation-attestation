from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
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
        return {finding.code for finding in attestation_check.validate_document(document, **kwargs)}

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
        mutation = copy.deepcopy(self.valid)
        mutation["verification"]["verifier"] = {
            "uri": mutation["subject"]["implementer"]["uri"],
            "kind": "protected-verifier",
        }
        self.assertIn(attestation_check.INDEPENDENCE, self.codes(mutation))

    def test_approved_decision_requires_all_checks_successful(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["checks"][0]["conclusion"] = "skipped"
        self.assertIn(attestation_check.DECISION, self.codes(mutation))

    def test_unknown_decision_outcome_and_unhashable_reasons_fail_closed(self) -> None:
        for forged_outcome in ("bypass", "pending", None, 1):
            mutation = copy.deepcopy(self.valid)
            mutation["decision"]["outcome"] = forged_outcome
            self.assertIn(attestation_check.DECISION, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["decision"] = {
            "outcome": "rejected",
            "allowedEffect": "pull-request.merge",
            "reasonCodes": [{"nested": "object"}],
        }
        self.assertIn(attestation_check.DECISION, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["decision"] = {
            "outcome": "rejected",
            "allowedEffect": "pull-request.merge",
            "reasonCodes": ["bad lowercase reason"],
        }
        self.assertIn(attestation_check.DECISION, self.codes(mutation))

    def test_boolean_pr_and_invalid_subject_identifiers_rejected(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["subject"]["pullRequest"] = True
        self.assertIn(attestation_check.SUBJECT, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["subject"]["ticket"] = "42"
        self.assertIn(attestation_check.SUBJECT, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["subject"]["correlationId"] = "short"
        self.assertIn(attestation_check.SUBJECT, self.codes(mutation))

    def test_invalid_timestamp_with_at_parameter_does_not_crash(self) -> None:
        at = datetime.fromisoformat("2026-08-14T12:30:00+00:00")
        mutation = copy.deepcopy(self.valid)
        mutation["validity"]["issuedAt"] = "2026-08-14"
        self.assertIn(attestation_check.SYNTAX, self.codes(mutation, at=at))

    def test_attestation_id_audience_conclusion_and_model_patterns(self) -> None:
        mutation = copy.deepcopy(self.valid)
        mutation["attestationId"] = "http://invalid/id"
        self.assertIn(attestation_check.SYNTAX, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["antiReplay"]["audience"] = "validation://audience/"
        self.assertIn(attestation_check.REPLAY, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["checks"][0]["conclusion"] = "unknown-state"
        mutation["decision"]["outcome"] = "rejected"
        mutation["decision"]["reasonCodes"] = ["CHECK-FAILED"]
        self.assertIn(attestation_check.CHECKS, self.codes(mutation))

        mutation = copy.deepcopy(self.valid)
        mutation["modelAdvice"]["model"] = "  "
        self.assertIn(attestation_check.DECISION, self.codes(mutation))

    def test_duplicate_json_keys_and_non_finite_numbers_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dup_path = Path(directory) / "duplicate.json"
            dup_path.write_text('{"schema":"a","schema":"b"}\n', encoding="utf-8")
            findings = attestation_check.load_and_validate(dup_path)
            self.assertEqual([attestation_check.SYNTAX], [item.code for item in findings])
            self.assertEqual(1, attestation_check.main(["validate", str(dup_path)]))

            link_path = Path(directory) / "symlink.json"
            link_path.symlink_to(self.valid_path)
            link_findings = attestation_check.load_and_validate(link_path)
            self.assertEqual([attestation_check.SYNTAX], [item.code for item in link_findings])
            self.assertEqual(1, attestation_check.main(["validate", str(link_path)]))
            self.assertEqual(1, attestation_check.main(["validate", directory]))

            deep_path = Path(directory) / "deep.json"
            deep_path.write_text('{"a":' * 5000 + "1" + "}" * 5000, encoding="utf-8")
            deep_findings = attestation_check.load_and_validate(deep_path)
            self.assertEqual([attestation_check.SYNTAX], [item.code for item in deep_findings])
            self.assertIn("nesting depth", deep_findings[0].message)
            self.assertEqual(1, attestation_check.main(["validate", str(deep_path)]))

            empty_dir = Path(directory) / "empty"
            empty_dir.mkdir()
            self.assertEqual(1, attestation_check.main(["validate", str(empty_dir)]))

    def test_unhashable_nested_fields_and_module_line_budgets(self) -> None:
        for mod_name in ("attestation_check.py", "attestation_primitives.py"):
            lines = len((ROOT / "src" / mod_name).read_text(encoding="utf-8").splitlines())
            self.assertLess(lines, 500, f"{mod_name} has {lines} lines")

        mutation = copy.deepcopy(self.valid)
        mutation["issuer"]["principal"]["kind"] = {"unhashable": 1}
        mutation["checks"][0]["conclusion"] = ["unhashable"]
        mutation["decision"]["outcome"] = {"unhashable": 1}
        mutation["signature"]["scheme"] = ["unhashable"]
        codes = self.codes(mutation)
        self.assertIn(attestation_check.SYNTAX, codes)
        self.assertIn(attestation_check.CHECKS, codes)
        self.assertIn(attestation_check.DECISION, codes)
        self.assertIn(attestation_check.SIGNATURE, codes)

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

        bad_uri = copy.deepcopy(self.profile)
        bad_uri["bindings"][0]["uri"] = "https://invalid/process"
        self.assertIn(attestation_check.PROFILE, self.codes(bad_uri))

        bad_meta = copy.deepcopy(self.profile)
        bad_meta["profileId"] = "invalid"
        bad_meta["version"] = "v1"
        self.assertIn(attestation_check.PROFILE, self.codes(bad_meta))

    def test_schema_is_closed_draft_2020_12(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "validation-attestation.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])
        for name in (
            "attestation",
            "profile",
            "principal",
            "issuer",
            "subject",
            "check",
            "decision",
            "modelAdvice",
            "validity",
            "antiReplay",
            "signature",
            "verification",
            "binding",
        ):
            self.assertFalse(schema["$defs"][name]["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
