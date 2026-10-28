import gzip
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dmarc_report_parser import load_paths, parse_report  # noqa: E402

SAMPLE = b"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <report_id>12345</report_id>
    <date_range><begin>1761609600</begin><end>1761695999</end></date_range>
  </report_metadata>
  <policy_published><domain>example.org</domain></policy_published>
  <record>
    <row>
      <source_ip>192.0.2.10</source_ip>
      <count>5</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.org</header_from></identifiers>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.7</source_ip>
      <count>2</count>
      <policy_evaluated><disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.org</header_from></identifiers>
  </record>
</feedback>
"""


class ParserTests(unittest.TestCase):
    def test_parse_report(self):
        recs = parse_report(SAMPLE)
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0].domain, "example.org")
        self.assertTrue(recs[0].dmarc_pass)
        self.assertFalse(recs[1].dmarc_pass)
        self.assertEqual(recs[1].count, 2)

    def test_load_gz(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "report.xml.gz"
            p.write_bytes(gzip.compress(SAMPLE))
            recs = load_paths([p])
            self.assertEqual(sum(r.count for r in recs), 7)


if __name__ == "__main__":
    unittest.main()
