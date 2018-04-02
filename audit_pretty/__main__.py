#!/usr/bin/python3

import sys
import re
import argparse

from audit_pretty import pretty_utils
from audit_pretty.parsers import pretty_printers, main_info_filters
from audit_pretty.frozendict import FrozenDict


string_types: dict = {
    1400: 'AVC'
}


def parse_message(line: str) -> dict:
    trimmed = line.strip()
    if len(trimmed) == 0 or 'audit' not in trimmed:
        return None
    if trimmed.startswith('['):
        # Reading from dmesg, strip timestamp and 'audit:' prefix.
        trimmed = re.sub(r'^\[\d+\.\d+\] audit: ', '', trimmed) 
    match = re.fullmatch(r'(type=\d+) audit\((\d+)\.\d+:\d+\): (.+)', trimmed)
    if match is None:
        return None
    trimmed = match.group(1) + ' ' + 'time=' + match.group(2) + ' ' + match.group(3)
    # audit message is a sequence of values in form key="value" or key='value' or key=value.
    # Value can contain whitespace so we can't just line.split().split('=').
    result = {}
    for match in re.finditer(r'([a-zA-Z\-\_]+)=(?:"(.+?)"|([^ ]+))', trimmed):
        if match.group(2) is not None:
            result[match.group(1)] = match.group(2)
        if match.group(3) is not None:
            result[match.group(1)] = match.group(3)
    for k, v in result.items():
        if v.isdigit():
            result[k] = int(v)
    return result


def setup_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
            description='Linux Auditing System logs pretty printer',
            epilog='Known message types: ' + ','.join(pretty_printers.keys()))

    parser.add_argument('-v', '--verbose', help='Include fields hidden by default.',
                        action='store_true')

    parser.add_argument('-m', '--merge', help='Print similar events only once.',
                        action='store_true')
    parser.add_argument('-c', '--count', help='Count similar events. Implies --merge. Will not work with dmesg -w or tail -f.',
                        action='store_true')

    parser.add_argument('--color', help='Use ANSI escape codes to color output.',
                        action='store_true', default=sys.stdout.isatty())
    parser.add_argument('--no-color', help='Don\'t use ANSI escape codes to color output.',
                        action='store_false', dest='color')

    parser.add_argument('--hide-unknown', help='Hide messages with unknown type instead of printing in raw format.',
                        action='store_true')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-e', '--exclude', help='Skip messages with this type. Can be specified multiple times.',
                       action='append', choices=pretty_printers.keys(), metavar='TYPE', default=[])
    group.add_argument('-i', '--only', help='Print only messages with this type. Can be specified multiple times.',
                       action='append', choices=pretty_printers.keys(), metavar='TYPE', default=[])

    return parser


def main():
    global args
    args = setup_argparse().parse_args()
    if args.count:
        args.merge = True
    if not args.color:
        pretty_utils.reset_styling()
    pretty_utils.verbose = args.verbose

    already_seen = dict()
    for line in sys.stdin:
        msg = parse_message(line)
        if msg is None:
            continue
        try:
            if type(msg['type']) == int:
                # dmesg log contains messages with numeric type.
                # Remap to string type for further processing.
                msg['type'] = string_types[msg['type']]

            if len(args.exclude) != 0 and msg['type'] in args.exclude or\
               len(args.only) != 0 and msg['type'] not in args.only:
                continue

            main_info = main_info_filters[msg['type']](msg)
            result = pretty_printers[msg['type']](msg)
            if result is None and not args.hide_unknown:
                print('Failed to format message, printing as is.')
                print(line)
            if args.merge:
                hashable_info = FrozenDict(main_info)
                if hashable_info not in already_seen.keys():
                    if not args.count:
                        print(result)
                already_seen[hashable_info] = already_seen.get(hashable_info, 0) + 1
            else:
                print(result)
        except KeyError:
            if len(args.only) == 0 and not args.hide_unknown:
                print('Unknown message type, printing as is.')
                print(line)

    if args.count:
        for info, count in already_seen.items():
            result = pretty_printers[info['type']](info, suffix='(' + str(count) + ')')
            if result is None and not args.hide_unknown:
                print('Failed to format message, printing as is.')
                print(line)
            print(result)


if __name__ == '__main__':
    main()

