import json
import sys
import unittest
from pathlib import Path
from unittest import mock


PIPELINE_DIR = Path(__file__).resolve().parents[1] / "pipeline"
if str(PIPELINE_DIR) not in sys.path:
    sys.path.insert(0, str(PIPELINE_DIR))

import qsb_run


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


class QsbRunSecurityTests(unittest.TestCase):
    def test_api_request_uses_authorization_header_not_query_string(self):
        captured = {}

        def fake_urlopen(request):
            captured["url"] = request.full_url
            captured["auth"] = request.get_header("Authorization")
            return _FakeResponse({"ok": True})

        with mock.patch.object(qsb_run, "API_KEY", "test-secret"), mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            payload = qsb_run.api_request("GET", "instances")

        self.assertEqual(payload, {"ok": True})
        self.assertEqual(captured["url"], f"{qsb_run.API_URL}/instances")
        self.assertEqual(captured["auth"], "Bearer test-secret")
        self.assertNotIn("api_key=", captured["url"])


if __name__ == "__main__":
    unittest.main()
