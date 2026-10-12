"""Regression for API downloads built as concatenated DOM link values."""

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "jsmine.py"


def mined_methods(source):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "app.js"
        path.write_text(source)
        result = subprocess.run([sys.executable, str(SCRIPT), str(path)],
                                check=True, capture_output=True, text=True)
    match = re.search(r"=== METHOD -> PATH .*?\n(.*?)(?=\n===|\Z)", result.stdout, re.S)
    return set(re.findall(r"(?m)^  ([A-Z]+\s+/\S+)", match.group(1)))


class JsminePlusHrefTest(unittest.TestCase):
    def test_minified_anchor_link_keeps_suffix_after_dynamic_id(self):
        methods = mined_methods(
            'const exportLink=h("a",{href:"/api/projects/"+project.id+"/export"});'
        )
        self.assertIn("GET    /api/projects/{...}/export", methods)
        self.assertNotIn("GET    /api/projects/", methods)

    def test_nested_expression_and_non_api_link(self):
        methods = mined_methods(
            'const file=h("a",{href:"/api/files/"+encodeURIComponent(file.id)+"/download"});'
            'const docs=h("a",{href:"/docs/"+id+"/manual"});'
        )
        self.assertIn("GET    /api/files/{...}/download", methods)
        self.assertFalse(any("/docs/" in line for line in methods))


if __name__ == "__main__":
    unittest.main()
