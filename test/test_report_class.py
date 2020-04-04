#   Copyright 2020 Yan Fitterer
#
#   Copying and distribution of this file, with or without modification,
#   are permitted in any medium without royalty provided the copyright
#   notice and this notice are preserved.  This file is offered as-is,
#   without any warranty.

import io
import os
import sys
import unittest
import xml.etree.ElementTree

from dmarc_rua_verify import RuaReport
from unittest.mock import Mock

class TestRuaReport(unittest.TestCase):
    def test_validate_domain_ok(self):
        xml_source = (
            '<?xml version="1.0" encoding="UTF-8" ?>'
            '<feedback>'
            '  <version>1.0</version>'
            '  <policy_published>'
            '    <domain>testdomain.com</domain>'
            '    <p>none</p>'
            '  </policy_published>'
            '</feedback>'
        )
        xml_tree = xml.etree.ElementTree.parse(io.StringIO(xml_source))
        report = RuaReport(xml_tree, set())
        report.validate_domain('testdomain.com')
        self.assertTrue(report.ok())

    def test_validate_domain_nodomain(self):
        xml_source = (
            '<?xml version="1.0" encoding="UTF-8" ?>'
            '<feedback>'
            '  <version>1.0</version>'
            '  <policy_published>'
            '    <p>none</p>'
            '  </policy_published>'
            '</feedback>'
        )
        xml_tree = xml.etree.ElementTree.parse(io.StringIO(xml_source))
        report = RuaReport(xml_tree, set())
        report.validate_domain('testdomain.com')
        self.assertFalse(report.ok())
        errs = report.errors
        self.assertEqual(len(errs), 1)
        self.assertTrue('expected 1 domain, found 0' in errs[0])

    def test_validate_domain_twodomains(self):
        xml_source = (
            '<?xml version="1.0" encoding="UTF-8" ?>'
            '<feedback>'
            '  <version>1.0</version>'
            '  <policy_published>'
            '  <domain>dom1.com</domain>'
            '  <domain>dom2.com</domain>'
            '    <p>none</p>'
            '  </policy_published>'
            '</feedback>'
        )
        xml_tree = xml.etree.ElementTree.parse(io.StringIO(xml_source))
        report = RuaReport(xml_tree, set())
        report.validate_domain('testdomain.com')
        self.assertFalse(report.ok())
        errs = report.errors
        self.assertEqual(len(errs), 2)
        self.assertTrue('expected 1 domain, found 2' in errs[0])
        self.assertTrue('domains found: dom1.com,dom2.com' in errs[1])

    def test__get_domain_dmarc_policy(self):
        xml_source = (
            '<?xml version="1.0" encoding="UTF-8" ?>'
            '<feedback/>'
        )
        xml_tree = xml.etree.ElementTree.parse(io.StringIO(xml_source))
        report = RuaReport(xml_tree, '')
        res = report._get_domain_dmarc_policy('none.nxtld')
        self.assertIsNone(res, msg='Got response from DNS on invalid domain')
        self.assertEqual(len(report.errors), 1,
                         msg='Not exactly 1 error on invalid domain')
        self.assertTrue('Failed to resolve' in report.errors[0],
                        msg='Wrong or missing error for invalid domain')

    def test_validate_policy_current_pass(self):
        xml_source = (
            '<?xml version="1.0" encoding="UTF-8" ?>'
            '<feedback>'
            '  <version>1.0</version>'
            '  <policy_published>'
            '  <domain>test.com</domain>'
            '    <p>reject</p>'
            '  </policy_published>'
            '</feedback>'
        )
        xml_tree = xml.etree.ElementTree.parse(io.StringIO(xml_source))
        report = RuaReport(xml_tree, set())
        dns_policy = 'v=DMARC1; p=reject;'
        report._get_domain_dmarc_policy = Mock(return_value=dns_policy)
        report.validate_policy_current('test.com')
        self.assertTrue(report.ok(), msg='Domain vs report policies mismatch')

    def test_validate_policy_current_fail(self):
        xml_source = (
            '<?xml version="1.0" encoding="UTF-8" ?>'
            '<feedback>'
            '  <version>1.0</version>'
            '  <policy_published>'
            '  <domain>test.com</domain>'
            '    <p>none</p>'
            '  </policy_published>'
            '</feedback>'
        )
        xml_tree = xml.etree.ElementTree.parse(io.StringIO(xml_source))
        report = RuaReport(xml_tree, set())
        dns_policy = 'v=DMARC1; p=reject;'
        report._get_domain_dmarc_policy = Mock(return_value=dns_policy)
        report.validate_policy_current('test.com')
        self.assertFalse(
            report.ok(), msg='Domain vs report policies match unexpectedly')
        self.assertEqual(
            len(report.errors), 1,msg='Not exactly 1 error on policy mismatch')
        self.assertTrue('DNS policy does not match' in report.errors[0],
                        msg='Wrong error string on policy mismatch')

    def test_validate_ips_pass(self):
        xml_source = (
            '<?xml version="1.0" encoding="UTF-8" ?>'
            '<feedback>'
            '  <version>1.0</version>'
            '  <record>'
            '    <row>'
            '      <source_ip>10.10.10.10</source_ip>'
            '    </row>'
            '  </record>'
            '  <record>'
            '    <row>'
            '      <source_ip>192.168.1.1</source_ip>'
            '    </row>'
            '  </record>'
            '</feedback>'
        )
        xml_tree = xml.etree.ElementTree.parse(io.StringIO(xml_source))
        domain_ips = set(('192.168.1.1','10.10.10.10'))
        report = RuaReport(xml_tree, domain_ips)
        report.validate_ips()
        self.assertTrue(
            report.ok(), msg='Domain and report IPs sets did not match')
        self.assertFalse(len(report.errors), msg='Unexpected errors')

    def test_validate_ips_fail(self):
        xml_source = (
            '<?xml version="1.0" encoding="UTF-8" ?>'
            '<feedback>'
            '  <version>1.0</version>'
            '  <record>'
            '    <row>'
            '      <source_ip>10.10.10.10</source_ip>'
            '    </row>'
            '  </record>'
            '</feedback>'
        )
        xml_tree = xml.etree.ElementTree.parse(io.StringIO(xml_source))
        domain_ips = set(('10.10.10.1'))
        report = RuaReport(xml_tree, domain_ips)
        report.validate_ips()
        self.assertFalse(
            report.ok(), msg='Domain and report IPs matched unexpectedly')
        self.assertEqual(len(report.errors), 1, msg='Unexpected errors count')
        self.assertTrue('do not match expected IPs' in report.errors[0],
                        msg='Error string mismatch on IPs check')

    def test_validate_from_pass(self):
        """Test two cases:
        1) a record with both fields (matching)
        2) a record with only one of the fields (ignored)"""
        xml_source = (
            '<?xml version="1.0" encoding="UTF-8" ?>'
            '<feedback>'
            '  <version>1.0</version>'
            '  <record>'
            '    <identifiers>'
            '      <header_from>domain.org</header_from>'
            '      <envelope_from>domain.org</envelope_from>'
            '    </identifiers>'
            '  </record>'
            '  <record>'
            '    <identifiers>'
            '      <envelope_from>domain.org</envelope_from>'
            '    </identifiers>'
            '  </record>'
            '</feedback>'
        )
        xml_tree = xml.etree.ElementTree.parse(io.StringIO(xml_source))
        report = RuaReport(xml_tree, set())
        report.validate_from()
        self.assertTrue(
            report.ok(), msg='Header and Envelope domain mismatch')
        self.assertFalse(len(report.errors), msg='Unexpected errors')

    def test_validate_from_fail(self):
        xml_source = (
            '<?xml version="1.0" encoding="UTF-8" ?>'
            '<feedback>'
            '  <version>1.0</version>'
            '  <record>'
            '    <identifiers>'
            '      <header_from>domain.org</header_from>'
            '      <envelope_from>other.org</envelope_from>'
            '    </identifiers>'
            '  </record>'
            '</feedback>'
        )
        xml_tree = xml.etree.ElementTree.parse(io.StringIO(xml_source))
        report = RuaReport(xml_tree, set())
        report.validate_from()
        self.assertFalse(
            report.ok(), msg='Header and Envelope domain match unexpectedly')
        self.assertEqual(len(report.errors), 1, msg='Incorrect error count')
        self.assertTrue('Mismatched from fields in header' in report.errors[0],
                        msg='Error text mismatch for "from" check')


if __name__ == '__main__':
    unittest.main()
