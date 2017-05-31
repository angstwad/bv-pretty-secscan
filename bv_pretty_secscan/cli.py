# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import re
import csv
import argparse
import functools
from collections import namedtuple

from termcolor import colored
from prettytable import PrettyTable


REGEXPS = (
    re.compile(r'^([\d.:]+);(?:[\w:-]+)\( instance_id: (i-[\w]+); region: ([\w-]+); stackName: ([\w-]+); service:\s?([\w-]+); role: ([\w-]+); vpc: ([\w-]+)\s?\)$'),  # noqa
    re.compile(r'^([\d.:]+);(?:[\w:-]+)\( instance_id:\s*(i-[\w]+); region:\s*([\w-]+); stackName:\s*([\w-]+); service:\s*([\w-]+); role:\s*([\w-]+); vpc:\s*([\w-]+)\s*\)$')  # noqa
)
CLEAN_REGEXP = re.compile('<.*?>')
FIELDS = [
    'IP/Port',
    'Instance',
    'Region',
    'Stack Name',
    'Service',
    'Role',
    'VPC'
]

Issue = namedtuple(
    'Issue', [
        'remediation',
        'severity',
        'info',
        'fix',
        'applies_to',
        'vulnerabilities',
        'assets'
    ]
)

red = functools.partial(colored, color='red')
blue = functools.partial(colored, color='blue')
green = functools.partial(colored, color='green')
yellow = functools.partial(colored, color='yellow')


bad_lines = []

def remove_html(string):
    return re.sub(CLEAN_REGEXP, '', string)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Pretty-printed Bazaarvoice Security Scan Reports'
    )
    parser.add_argument(
        'file',
        type=argparse.FileType('rb'),
        help='Security scan report CSV file to process'
    )
    parser.add_argument(
        '--fields',
        nargs='*',
        choices=FIELDS,
        help='Limit table to specific columns by column name. Please note '
             'that this is case sensitive.'
    )
    parser.add_argument(
        '--show-unparsed-lines',
        action='store_true',
        help='Show lines that could not be parsed.'
    )
    return parser.parse_args()


def get_matches(asset_list):
    for asset in asset_list:
        match = None
        for regexp in REGEXPS:
            match = re.match(regexp, asset)
            if not match:
                continue
            yield match
        if match is None:
            bad_lines.append(asset)


def make_table(assets):
    split = assets.split('\n')
    matches = get_matches(asset for asset in split if asset)
    table = PrettyTable(field_names=FIELDS)
    for match in matches:
        table.add_row(match.groups())
    table.align = 'l'
    return table


def main():
    args = parse_args()

    try:
        assert args.file.name.lower().endswith('.csv'), 'File is not a CSV.'
    except AssertionError as e:
        raise SystemExit(e)

    reader = csv.reader(args.file)
    next(reader)  # intentionally skip the headers

    issues = []
    for line in reader:
        try:
            remed, sev, info, fix, appl, vuln = line[:-1]
        except ValueError:
            raise SystemExit(
                'Error processing file: content has unexpected format')

        fix = ' '.join(line.strip() for line in fix.split('\n'))
        vuln = ', '.join(line for line in vuln.split('\n') if line)

        table = make_table(line[-1])
        table_str = table.get_string(fields=args.fields or FIELDS)

        issue = Issue(remed, sev, info, fix, appl, vuln, table_str)
        issues.append(issue)

    for index, issue in enumerate(issues):
        issue_severity = issue.severity.strip().lower()
        if issue_severity == 'severe':
            severity = red(issue.severity)
        elif issue_severity == 'moderate':
            severity = yellow(issue.severity)
        else:
            severity = green(issue.severity)

        if index > 0:
            print('\n' * 3)
        print(blue('Remediation: ') + yellow(issue.remediation))
        print(blue('Severity: ') + severity)
        print(blue('Info: ') + yellow(issue.info or 'None'))
        print(blue('Fix: ' + yellow(remove_html(issue.fix))))
        print(blue('Applies To: ') + yellow(issue.applies_to or 'None'))
        print(blue('Vulnerabilities: ') + yellow(issue.vulnerabilities))
        print()
        print(issue.assets)

    if bad_lines and not args.show_unparsed_lines:
        print('\n' * 3)
        print('There were some lines that could not be parsed.  Use '
              '"--show-unparsed-lines" to see them.')

    elif bad_lines and args.show_unparsed_lines:
        print('\n' * 3)
        print(red('The following lines could not be parsed:'))
        [print(line) for line in bad_lines]


if __name__ == '__main__':
    main()
