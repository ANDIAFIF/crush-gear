#!/usr/bin/env python3
"""Simple test runner without pytest dependency."""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from test_feed_parser import TestParseNuclei

def run_tests():
    """Run all tests and report results."""
    test_class = TestParseNuclei()
    tests = [
        ("test_parse_cve_findings", test_class.test_parse_cve_findings),
        ("test_parse_non_cve_findings", test_class.test_parse_non_cve_findings),
        ("test_parse_multiple_cves_single_finding", test_class.test_parse_multiple_cves_single_finding),
        ("test_skip_progress_lines", test_class.test_skip_progress_lines),
        ("test_empty_file", test_class.test_empty_file),
        ("test_missing_file", test_class.test_missing_file),
        ("test_malformed_json", test_class.test_malformed_json),
    ]

    passed = 0
    failed = 0
    errors = []

    print("=" * 70)
    print("Running Feed Parser Tests")
    print("=" * 70)

    for test_name, test_func in tests:
        try:
            test_func()
            print(f"✓ {test_name}")
            passed += 1
        except AssertionError as e:
            print(f"✗ {test_name}")
            print(f"  AssertionError: {e}")
            failed += 1
            errors.append((test_name, str(e)))
        except Exception as e:
            print(f"✗ {test_name}")
            print(f"  Error: {e}")
            failed += 1
            errors.append((test_name, str(e)))

    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 70)

    if errors:
        print("\nFailed tests:")
        for test_name, error in errors:
            print(f"  - {test_name}: {error}")
        sys.exit(1)
    else:
        print("\n✓ All tests passed!")
        sys.exit(0)

if __name__ == "__main__":
    run_tests()
