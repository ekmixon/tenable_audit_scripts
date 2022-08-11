#!/usr/bin/env python3

# Description : Reads in a directory of powershell scripts and generates an
#               audit file with each of the scripts as an encoded 
#               AUDIT_POWERSHELL check.


import argparse
import base64
import datetime
import os
import re
import sys


show_verbose = False
show_time = False

setting_re = re.compile('^# *([^ ]+) *: *(.*) *$', re.M)

def parse_args(parameters):
    global show_time, show_verbose

    default_audit = 'output.audit'

    parser = argparse.ArgumentParser(description=('Convert powershell scripts '
                                                  'into audit items '))

    parser.add_argument('-E', '--encode', action='store_true',
                        help='encode checks into base64')

    parser.add_argument('-t', '--timestamp', action='store_true',
                        help='show timestamp on output')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='show verbose output')

    parser.add_argument(
        '-o',
        '--output',
        nargs=1,
        default=default_audit,
        help=f'output audit name: {default_audit}',
    )


    parser.add_argument('powershell', nargs=1, type=str,
                        help='location of powershell files')

    args = parser.parse_args(parameters)

    if args.timestamp:
        show_time = True
    if args.verbose:
        show_verbose = True

    args.output = list_or_string(args.output)
    args.powershell = list_or_string(args.powershell)

    return args


def list_or_string(target=None):
    if isinstance(target, list):
        return target[0] if len(target) > 0 else None
    return target


def display(message, verbose=False, exit=0):
    global show_time, show_verbose

    if show_time:
        now = datetime.datetime.now()
        timestamp = datetime.datetime.strftime(now, '%Y/%m/%d %H:%M:%S')
        message = f'{timestamp} {message}'

    out = sys.stderr if exit > 0 else sys.stdout
    if verbose and show_verbose or not verbose:
        out.write(message.rstrip() + '\n')
    if exit > 0:
        sys.exit(exit)


def get_ps_scripts(location):
    scripts = []

    if os.path.isdir(location):
        for (root, dirs, files) in os.walk(location):
            scripts.extend(
                os.path.join(root, filename)
                for filename in files
                if filename.endswith('.ps1')
            )

    elif os.path.isfile(location):
        if location.endswith('.ps1'):
            scripts.append(os.path.join(location))

    if not scripts:
        display('[!] ERROR: source powershell location not found', exit=True)

    return scripts


def encode_script(content):
    return base64.b64encode(content.encode('utf-16le')).decode('ascii')


def convert_script_to_item(source, encode=False):
    global setting_re

    basename = '.'.join(os.path.basename(source).split('.')[:-1])

    script = ''
    with open(source, 'r') as s_in:
        script = s_in.read().strip()

    settings = {key.lower(): val for key, val in setting_re.findall(script)}
    content = ''
    encoded = 'NO'
    if encode:
        content = encode_script(script)
        encoded = 'YES'
    else:
        content = script.replace("'", "\\'")

    desc = settings.get('name', f'PS: {basename}')
    expect = settings.get('expect', 'ManualReview')
    check_type = f"CHECK_{settings.get('type', 'REGEX')}"

    item = '''<custom_item>
  type                 : AUDIT_POWERSHELL
  description          : "{}"
  value_type           : POLICY_TEXT
  value_data           : "{}"
  powershell_args      : '{}'
  ps_encoded_args      : {}
  check_type           : {}
</custom_item>
'''

    check = item.format(desc, expect, content, encoded, check_type)

    display(f'[-]   {source}: "{desc}" is expecting "{expect}"')

    return check


def output_audit(items, output):
    content = '''<check_type:"Windows" version:"2">
<group_policy:"Auto-gened: {}">

{}

</group_policy>
</check_type>'''

    now = datetime.datetime.now()
    audit = content.format(now, '\n\n'.join(items).strip())

    with open(output, 'w') as s_out:
        s_out.write(audit.strip() + '\n')


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])
    display('[+] Start', verbose=True)

    display(f'[+] Retrieving powershell scripts from "{args.powershell}"')
    scripts = get_ps_scripts(args.powershell)
    display(f"[-]   found {len(scripts)} script{'s' * (len(scripts) - 1)}")

    items = []
    display('[+] Processing scripts')
    for script in scripts:
        item = convert_script_to_item(script, args.encode)
        if item is not None:
            items.append(item)

    display(f'[+] Writing audit: {args.output}')
    output_audit(items, args.output)

    display('[+] Done', verbose=True)

