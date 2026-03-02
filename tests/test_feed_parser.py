"""Unit tests for core/feed.py parsers."""

import json
import tempfile
from pathlib import Path
from core.feed import parse_nuclei


class TestParseNuclei:
    """Test nuclei JSON parser."""

    def test_parse_cve_findings(self):
        """Test parsing findings with CVE IDs."""
        # Create temp nuclei.json with CVE finding
        with tempfile.TemporaryDirectory() as tmpdir:
            nuclei_file = Path(tmpdir) / "nuclei.json"
            finding = {
                "template-id": "CVE-2021-44228-rce",
                "info": {
                    "name": "Log4j RCE",
                    "severity": "critical",
                    "classification": {
                        "cve-id": "CVE-2021-44228"
                    }
                },
                "host": "http://vulnerable.com",
                "matched-at": "http://vulnerable.com:8080"
            }
            nuclei_file.write_text(json.dumps(finding))

            # Parse
            findings = parse_nuclei(Path(tmpdir))

            # Verify
            assert len(findings) == 1
            assert findings[0]["cve"] == "CVE-2021-44228"
            assert findings[0]["template_id"] == "CVE-2021-44228-rce"
            assert findings[0]["severity"] == "critical"
            assert findings[0]["host"] == "http://vulnerable.com"

    def test_parse_non_cve_findings(self):
        """Test parsing findings WITHOUT CVE IDs (like weak-cipher-suites)."""
        # Create temp nuclei.json with non-CVE finding
        with tempfile.TemporaryDirectory() as tmpdir:
            nuclei_file = Path(tmpdir) / "nuclei.json"
            finding = {
                "template": "ssl/weak-cipher-suites.yaml",
                "template-id": "weak-cipher-suites",
                "info": {
                    "name": "Weak Cipher Suites Detection",
                    "severity": "low"
                },
                "host": "example.com",
                "matched-at": "example.com:443"
            }
            nuclei_file.write_text(json.dumps(finding))

            # Parse
            findings = parse_nuclei(Path(tmpdir))

            # Verify - THIS IS THE FIX!
            assert len(findings) == 1, "Non-CVE findings should be included"
            assert findings[0]["cve"] is None, "CVE should be None for non-CVE findings"
            assert findings[0]["template_id"] == "weak-cipher-suites"
            assert findings[0]["severity"] == "low"
            assert findings[0]["host"] == "example.com"

    def test_parse_multiple_cves_single_finding(self):
        """Test parsing finding with multiple CVE IDs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nuclei_file = Path(tmpdir) / "nuclei.json"
            finding = {
                "template-id": "multi-cve-vuln",
                "info": {
                    "name": "Multiple CVE Vulnerability",
                    "severity": "high",
                    "classification": {
                        "cve-id": ["CVE-2020-1234", "CVE-2020-5678"]
                    }
                },
                "host": "http://target.com"
            }
            nuclei_file.write_text(json.dumps(finding))

            # Parse
            findings = parse_nuclei(Path(tmpdir))

            # Verify - should create 2 separate findings
            assert len(findings) == 2
            assert findings[0]["cve"] == "CVE-2020-1234"
            assert findings[1]["cve"] == "CVE-2020-5678"

    def test_skip_progress_lines(self):
        """Test that progress/stats lines are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nuclei_file = Path(tmpdir) / "nuclei.json"
            content = [
                # Progress line - should be skipped
                '{"duration":"0:00:30","errors":"0","hosts":"3","matched":"0"}',
                # Real finding - should be included
                '{"template-id":"test-vuln","info":{"severity":"low"},"host":"test.com"}'
            ]
            nuclei_file.write_text("\n".join(content))

            # Parse
            findings = parse_nuclei(Path(tmpdir))

            # Verify - only 1 finding (progress line skipped)
            assert len(findings) == 1
            assert findings[0]["template_id"] == "test-vuln"

    def test_empty_file(self):
        """Test parsing empty nuclei.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nuclei_file = Path(tmpdir) / "nuclei.json"
            nuclei_file.write_text("")

            findings = parse_nuclei(Path(tmpdir))
            assert len(findings) == 0

    def test_missing_file(self):
        """Test parsing when nuclei.json doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = parse_nuclei(Path(tmpdir))
            assert len(findings) == 0

    def test_malformed_json(self):
        """Test that malformed JSON lines are skipped gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nuclei_file = Path(tmpdir) / "nuclei.json"
            content = [
                'invalid json line',
                '{"template-id":"valid","info":{"severity":"low"},"host":"test.com"}'
            ]
            nuclei_file.write_text("\n".join(content))

            # Parse - should skip invalid line
            findings = parse_nuclei(Path(tmpdir))
            assert len(findings) == 1
            assert findings[0]["template_id"] == "valid"


if __name__ == "__main__":
    # Run tests directly
    print("Use run_tests.py to execute tests")
