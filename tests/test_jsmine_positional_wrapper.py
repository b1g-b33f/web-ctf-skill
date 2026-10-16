"""Regression for prefixed request helpers with a positional HTTP method."""

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "jsmine.py"


class JsminePositionalWrapperTest(unittest.TestCase):
    def test_prefixed_wrapper_preserves_route_and_positional_method(self):
        source = '''
async function x(path, verb="GET", payload) {
  const response = await fetch("/gateway" + path, {
    method: verb,
    body: payload === undefined ? undefined : JSON.stringify(payload)
  });
  return response.json();
}
x("/teams/" + team.id + "/invites", "POST", {email: contact, access: "viewer"});
x("/invitations/accept", "POST", {token: invitation, access: "viewer"});
x("/me");
'''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "client.js"
            path.write_text(source)
            result = subprocess.run([sys.executable, str(SCRIPT), str(path)],
                                    check=True, capture_output=True, text=True)
        match = re.search(r"=== METHOD -> PATH .*?\n(.*?)(?=\n===|\Z)",
                          result.stdout, re.S)
        self.assertIsNotNone(match, result.stdout)
        methods = set(re.findall(r"(?m)^  ([A-Z]+\s+/\S+)", match.group(1)))
        self.assertIn("POST   /gateway/teams/{...}/invites", methods)
        self.assertIn("POST   /gateway/invitations/accept", methods)
        self.assertIn("GET    /gateway/me", methods)
        self.assertNotIn("GET    /gateway/invitations/accept", methods)
        self.assertNotIn("POST   /invitations/accept", methods)


if __name__ == "__main__":
    unittest.main()
