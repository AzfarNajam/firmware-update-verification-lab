"""Integration checks exercise upstream crypto, plus harness error classification."""
from pathlib import Path
import subprocess
import tempfile
import unittest

import lab


class VerificationEvidenceTests(unittest.TestCase):
    def test_tool_errors_are_not_security_rejections(self):
        for code, output in [(1, ""), (2, "Usage error"), (0, "unexpected output")]:
            with self.subTest(code=code, output=output):
                result = subprocess.CompletedProcess([], code, output, "tool failed")
                self.assertEqual(lab.classify_verification(result), "ERROR")

    def test_real_images_and_public_key_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            report = lab.run_demo(Path(directory))
            cases = {c["name"]: c for c in report["cases"]}
            self.assertEqual(report["total"], 5)
            self.assertEqual(report["passed"], 5, report)
            run = Path(report["run_dir"])
            original = (run / "signed-v2.bin").read_bytes()
            changed = (run / "tampered-v2.bin").read_bytes()
            self.assertEqual(len(original), len(changed))
            differences = [i for i, (a, b) in enumerate(zip(original, changed)) if a != b]
            self.assertEqual(differences, [lab.HEADER_SIZE + 10])
            public = (run / "keys" / "manufacturer-public.pem").read_text()
            self.assertIn("BEGIN PUBLIC KEY", public)
            self.assertNotIn("PRIVATE", public)
            self.assertEqual(cases["valid_signature"]["observed"], "ACCEPT")
            self.assertEqual(cases["changed_payload"]["observed"], "REJECT")
            self.assertEqual(cases["untrusted_signer"]["observed"], "REJECT")
            self.assertEqual(cases["old_signed_image"]["observed"], "ACCEPT")
            self.assertEqual(cases["hash_only_control"]["observed"], "ACCEPT")
            self.assertIsNone(cases["hash_only_control"]["verification_key"])
            # A missing input must fail the harness, not count as a rejected attack.
            missing = lab.imgtool("verify", "--key", run / "keys" / "manufacturer-public.pem",
                                  run / "does-not-exist.bin")
            self.assertEqual(lab.classify_verification(missing), "ERROR")


if __name__ == "__main__":
    unittest.main()
