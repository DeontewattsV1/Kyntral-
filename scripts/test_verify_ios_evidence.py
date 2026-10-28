"""Exercise the release gate's failure paths independently of Xcode."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("evidence", Path(__file__).with_name("verify-ios-evidence.py"))
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class EvidenceGateTests(unittest.TestCase):
    def node(self, result="Passed"):
        return {"nodeType": "Test Case", "testIdentifier": "Suite/testExample()", "result": result}

    def test_accepts_passed_case(self):
        self.assertEqual(evidence.verify_results([self.node()], {"Suite/testExample"}), 1)

    def test_rejects_missing_case(self):
        with self.assertRaises(ValueError):
            evidence.verify_results([], {"Suite/testExample"})

    def test_rejects_skipped_failed_or_duplicate_case(self):
        for nodes in [[self.node("Skipped")], [self.node("Failed")], [self.node(), self.node()]]:
            with self.subTest(nodes=nodes), self.assertRaises(ValueError):
                evidence.verify_results(nodes, {"Suite/testExample"})


if __name__ == "__main__":
    unittest.main()
