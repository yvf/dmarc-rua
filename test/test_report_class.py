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
        ip = '192.168.1.1'
        report = RuaReport(xml_tree, ip)
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
        ip = '192.168.1.1'
        report = RuaReport(xml_tree, ip)
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
        ip = '192.168.1.1'
        report = RuaReport(xml_tree, ip)
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
        report = RuaReport(xml_tree, '')
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
        report = RuaReport(xml_tree, '')
        dns_policy = 'v=DMARC1; p=reject;'
        report._get_domain_dmarc_policy = Mock(return_value=dns_policy)
        report.validate_policy_current('test.com')
        self.assertFalse(
            report.ok(), msg='Domain vs report policies match unexpectedly')
        self.assertEqual(
            len(report.errors), 1,msg='Not exactly 1 error on policy mismatch')
        self.assertTrue('DNS policy does not match' in report.errors[0],
                        msg='Wrong error string on policy mismatch')


if __name__ == '__main__':
    unittest.main()