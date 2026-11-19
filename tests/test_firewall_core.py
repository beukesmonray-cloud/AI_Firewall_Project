import base64
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
import re
from unittest.mock import patch

import firewall_core


class FirewallPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.application = Path(self.temp_directory.name) / "sample.exe"
        self.application.write_bytes(b"test executable placeholder")

    def make_event(self, **overrides):
        event = {
            "record_id": 123,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": firewall_core.WFP_OUTBOUND_DIRECTION,
            "application": str(self.application),
            "destination_address": "8.8.8.8",
            "destination_port": "443",
            "protocol": "6",
        }
        event.update(overrides)
        return event

    def test_valid_outbound_event_is_narrowly_normalized(self):
        candidate, reason = firewall_core.validate_outbound_event(self.make_event())

        self.assertEqual(reason, "eligible outbound event")
        self.assertEqual(candidate["remote_address"], "8.8.8.8")
        self.assertEqual(candidate["remote_port"], 443)
        self.assertEqual(candidate["protocol"], "TCP")

    def test_inbound_private_and_unsupported_events_are_rejected(self):
        cases = (
            ({"direction": "%%14592"}, "not an outbound"),
            ({"destination_address": "192.168.1.1"}, "globally routable"),
            ({"protocol": "1"}, "only TCP and UDP"),
        )
        for overrides, expected_reason in cases:
            with self.subTest(overrides=overrides):
                candidate, reason = firewall_core.validate_outbound_event(
                    self.make_event(**overrides)
                )
                self.assertIsNone(candidate)
                self.assertIn(expected_reason, reason)

    def test_scores_below_threshold_do_not_create_rules(self):
        with patch("firewall_core._create_temporary_block") as create_rule:
            result, reason = firewall_core.evaluate_and_apply(self.make_event(), 89)

        self.assertIsNone(result)
        self.assertIn("below", reason)
        create_rule.assert_not_called()

    def test_threshold_score_creates_scoped_rule(self):
        expected = {"rule_name": "AI_Firewall_Project_test", "created": True}
        with patch("firewall_core._create_temporary_block", return_value=expected) as create_rule:
            result, reason = firewall_core.evaluate_and_apply(self.make_event(), 90)

        self.assertEqual(result, expected)
        self.assertEqual(reason, "temporary outbound block applied")
        create_rule.assert_called_once()

    def test_core_windows_process_is_rejected(self):
        core_application = Path(self.temp_directory.name) / "svchost.exe"
        core_application.write_bytes(b"test executable placeholder")

        candidate, reason = firewall_core.validate_outbound_event(
            self.make_event(application=str(core_application))
        )

        self.assertIsNone(candidate)
        self.assertIn("core Windows", reason)

    def test_collector_parses_new_event_records(self):
        returned_event = {
            "record_id": 124,
            "direction": firewall_core.WFP_OUTBOUND_DIRECTION,
            "application": str(self.application),
            "destination_address": "8.8.8.8",
            "destination_port": "443",
            "protocol": "6",
        }
        with patch(
            "firewall_core._run_powershell",
            return_value=json.dumps([returned_event]),
        ) as run_powershell:
            events = firewall_core.collect_events_after(123)

        self.assertEqual(events, [returned_event])
        self.assertIn("EventID=5156", run_powershell.call_args.args[0])
        script = run_powershell.call_args.args[0]
        self.assertIn("$after = 123", script)
        self.assertIn("EventRecordID > $after", script)

    def test_rule_creation_is_scoped_and_expires_after_policy_lifetime(self):
        quoted_application = Path(self.temp_directory.name) / "app's.exe"
        quoted_application.write_bytes(b"test executable placeholder")
        candidate, reason = firewall_core.validate_outbound_event(
            self.make_event(application=str(quoted_application))
        )
        self.assertEqual(reason, "eligible outbound event")
        response = {"rule_name": firewall_core._rule_identity(candidate)[0], "created": True}

        with patch(
            "firewall_core._run_powershell",
            return_value=json.dumps(response),
        ) as run_powershell:
            result = firewall_core._create_temporary_block(candidate)

        script = run_powershell.call_args.args[0]
        self.assertEqual(result, response)
        self.assertIn("-Direction Outbound", script)
        self.assertIn("-RemoteAddress $payload.remote_address", script)
        self.assertIn("-RemotePort ([int]$payload.remote_port)", script)
        self.assertIn("-Protocol $payload.protocol", script)
        self.assertIn(
            f"AddHours({firewall_core.RULE_LIFETIME_HOURS})",
            script,
        )
        self.assertNotIn(str(quoted_application), script)
        payload_match = re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", script)
        self.assertIsNotNone(payload_match)
        decoded_payload = json.loads(base64.b64decode(payload_match.group(1)))
        self.assertEqual(decoded_payload["application"], str(quoted_application))


if __name__ == "__main__":
    unittest.main()
