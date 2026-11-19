import json
import unittest
from unittest.mock import patch

import ai_security


class CalculateRiskTests(unittest.TestCase):
    def setUp(self):
        self.urlopen_patch = patch("ai_security.urllib.request.urlopen")
        self.response = self.urlopen_patch.start()
        self.addCleanup(self.urlopen_patch.stop)

    def set_model_response(self, risk):
        response_body = json.dumps(
            {"response": json.dumps({"risk": risk})}
        ).encode("utf-8")
        context = self.response.return_value.__enter__.return_value
        context.read.return_value = response_body

    def test_posts_events_and_returns_model_risk(self):
        self.set_model_response(42)

        self.assertEqual(ai_security.calculate_risk([{"event": "test"}]), 42)

        request = self.response.call_args.args[0]
        self.assertEqual(request.full_url, ai_security.OLLAMA_URL)
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["model"], ai_security.OLLAMA_MODEL)
        self.assertIn('"event": "test"', payload["prompt"])

    def test_clamps_risk_to_supported_range(self):
        for model_risk, expected in ((-3, 0), (150, 100)):
            with self.subTest(model_risk=model_risk):
                self.set_model_response(model_risk)
                self.assertEqual(ai_security.calculate_risk([]), expected)

    def test_rejects_non_numeric_risk(self):
        self.set_model_response("unknown")

        with self.assertRaises(ValueError):
            ai_security.calculate_risk([])


if __name__ == "__main__":
    unittest.main()
