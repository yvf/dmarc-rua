#   Copyright 2020 Yan Fitterer
#
#   Copying and distribution of this file, with or without modification,
#   are permitted in any medium without royalty provided the copyright
#   notice and this notice are preserved.  This file is offered as-is,
#   without any warranty.

# Simple utility that consumes a DMARC rua report and asserts
# a number of facts on that report. Exits 0 when no issues are found,
# 1 if one or more of the assertions failed, and 2 if it failed
# to run successfully (parse errors, unexpected report format, etc...)
#
# The DMARC rua format is documented in RFC7489 Appendix C
# https://tools.ietf.org/html/rfc7489#appendix-C
# This simple tool implements minimally what I need for my
# personal use on a single domain.

import click
import dns.resolver
import email.parser
import email.policy
import gzip
import io
import logging
import logging.config
import sys
import xml.etree.ElementTree
import zipfile

from typing import List, Optional, TextIO, Union

log = None
def init_logging() -> None:
    logging_config = dict(
        version = 1,
        formatters = {
            'fmt': {'format':
                    '%(asctime)s %(levelname)-8s %(message)s',
                    'datefmt': '%Y-%m-%d %H:%M:%S'}
            },
        handlers = {
            'h': {'class': 'logging.StreamHandler',
                  'formatter': 'fmt',
                  'level': logging.DEBUG}
            },
        root = {
            'handlers': ['h'],
            'level': logging.DEBUG,
            },
    )

    logging.config.dictConfig(logging_config)

    global log
    log = logging.getLogger()

class RuaReport(object):
    """Object representing the aggregated report, with methods to validate
    the various facts of interest"""
    def __init__(self, xml: xml.etree.ElementTree.ElementTree, domain_ips: set):
        self.xml = xml
        self.root = xml.getroot()
        self.domain_ips = domain_ips
        self.errors: List[str] = []

    def ok(self) -> bool:
        return not bool(len(self.errors))

    def validate_domain(self, expected_domain: str) -> None:
        """Expect one policy, with a single domain"""
        domains = self.root.findall('./policy_published/domain')
        if not len(domains) == 1: # should be 1, but standard is not strict
            count = len(domains)
            self.errors.append(f'Domain validation: expected 1 domain, found {count}')
            if count > 1:
                found = ','.join([x.text for x in domains])
                self.errors.append(f'Domain validation: domains found: {found}')
            return

        found_domain = domains[0].text
        if found_domain != expected_domain:
            self.errors.append(f'Unexpected domain in report published policy: {found_domain}')

    def _get_domain_dmarc_policy(self, domain: str) -> Optional[str]:
        """Split out the DNS lookup for testing purposes."""
        dmarc_host = '_dmarc.' + domain
        try:
            answers = dns.resolver.query(dmarc_host, 'TXT')
        except Exception as e:
            self.errors.append(f'Failed to resolve dmarc record {dmarc_host}: {e}')
            return

        if len(answers) != 1:
            self.errors.append('policy dns lookup failed: expected exactly 1 answer')
            return

        return answers[0].to_text().strip('"')

    def validate_policy_current(self, domain: str) -> None:
        """Validate that the dns policy is consistent with the report's"""
        dns_txt = self._get_domain_dmarc_policy(domain)
        dns_rec = dict([x.strip().split('=') for x in dns_txt.split(';') if x])

        report_policy = self.root.findall('./policy_published/p')
        if len(report_policy) != 1:
            self.errors.append('report does not have exactly 1 published policy')
            return

        dns_pol = dns_rec['p']
        report_pol = report_policy[0].text
        if dns_pol != report_pol:
            msg = f'DNS policy does not match report policy ({dns_pol} != {report_pol})'
            self.errors.append(msg)

    def validate_ips(self) -> None:
        """Ensure there are no unexpected source IPs in any of the 'record' entries.
        As per the standard, there must be at least one record, and each must have at
        exactly one row/source_ip element"""
        report_ips = set([e.text for e in self.root.findall('./record/row/source_ip')])
        if not report_ips == self.domain_ips:
            msg = f'IPs in report ({report_ips}) do not match expected IPs ({self.domain_ips})'
            self.errors.append(msg)

    def validate_from(self) -> None:
        """For each set of messages (record elements), if there are both
        header_from and enveloppe_from elements, verify that they are the same
        (domain)."""
        records = self.root.findall('./record/identifiers')
        for record_ids in records:
            header = record_ids.find('header_from')
            envelope = record_ids.find('envelope_from')
            if header is not None and envelope is not None: # not all respect standard
                if header.text != envelope.text:
                    msg = f'Mismatched from fields in header ({header}) and envelope ({envelope})'
                    self.errors.append(msg)

    def validate_dkim_spf(self) -> None:
        """For our own IPs, we expect 100% pass on dkim and spf checks. For others
        100% failure"""
        for record in self.root.findall('./record'):
            source_ip = record.find('./row/source_ip').text
            dkim = record.find('./auth_results/dkim/result')
            spf = record.find('./auth_results/spf/result')
            if source_ip in self.domain_ips:
                if dkim and dkim.text != 'pass':
                    self.errors.append('DKIM failed for our host ({source_ip}')
                if spf and spf.text != 'pass':
                    self.errors.append('SPF failed for our host ({source_ip}')
            else:
                if dkim and dkim.text == 'pass':
                    self.errors.append('DKIM succeeded for foreign host ({source_ip}')
                if spf and spf.text == 'pass':
                    self.errors.append('SPF succeeded for foreign host ({source_ip}')


def fatal(msg: str):
    log.critical(msg)
    sys.exit(2)

def extract_xml(source: Union[str, TextIO]) -> io.StringIO:
    """Takes an SMTP message with a single attachment,
    extracts it, and returnsit as a file-like object. Handles
    multipart mime messages (yahoo, others...) as well as
    Google's minimalist application/zip messages"""

    if not hasattr(source, 'read'):
        source = open(source, 'r')

    parser = email.parser.Parser(policy=email.policy.default)
    email_msg = parser.parse(source)
    source.close()

    if email_msg.get_content_type() == 'application/zip': # google
        zip_data = email_msg.get_content()
        zf = zipfile.ZipFile(io.BytesIO(zip_data))
        filenames = zf.namelist()
        if len(filenames) != 1:
            cnt = len(filenames)
            raise RuntimeError(f'Not exactly one file in attached zip file ({cnt} found)')
        xml = zf.read(filenames[0])
        xml_fd = io.StringIO(xml.decode())
    else:
        attachments = list(email_msg.iter_attachments())
        if not len(attachments) == 1:
            cnt = len(attachments)
            raise RuntimeError(f'Not exactly one attachment in mail ({cnt} found)')
        compressed_data = attachments[0].get_content()
        xml_fd = io.StringIO(gzip.decompress(compressed_data).decode())

    return xml_fd

domain_mx_ips = set()
def get_domain_mx(ctx, param, value) -> set:
    ips = set()
    try:
        answers = dns.resolver.query(value, 'MX')
        for answer in answers:
            name = answer.exchange.canonicalize().to_text()
            for answer in dns.resolver.query(name, 'A'):
                ips.add(answer.to_text())
    except Exception as e:
        fatal(f'DNS resolver failure: {e}')

    global domain_mx_ips
    domain_mx_ips = ips

    log.debug(f'found domain mx ips: {domain_mx_ips}')

    return value

def split_ips(ctx, param, value) -> set:
    if isinstance(value, str):
        return set(value.split(','))
    else:
        return value


@click.command()
@click.option('--domain', required=True, callback=get_domain_mx,
              help='The FQDN the report is for')
# default in read-from is redundant, but won't work without it. Maybe a click bug.
@click.option('--source', help='Optional file to read from', default=sys.stdin)
@click.option('--input-format', type=click.Choice(['xml', 'smtp']),
              help='smtp format consumes raw email (RFC 5322)')
@click.option('--ip', default=lambda: domain_mx_ips, callback=split_ips,
              help='Expected source IPs, comma separated. Defaults to MX hosts for domain.')
def main(domain, ip, source, input_format='xml'):
    """Process a DMARC rua report and check for various error conditions.

    If any error is found, exit 1. Exit 2 if the program is not
    able to run successfully."""

    log.debug(f'Data is being read from: {source}')

    try:
        if input_format == 'smtp':
            source = extract_xml(source)
        xml_tree = xml.etree.ElementTree.parse(source)
    except Exception as e:
        fatal(str(e))

    # initialize the report object with the xml data
    report = RuaReport(xml_tree, ip)

    success = True
    msgs = []

    # Run the tests
    report.validate_domain(domain)
    report.validate_policy_current(domain)
    report.validate_ips()
    report.validate_from()
    report.validate_dkim_spf()

    # Report errors (if any) and exit
    if not report.ok():
        for msg in report.errors:
            log.error(msg)
        sys.exit(1)


if __name__ == '__main__':
    init_logging()
    main()
