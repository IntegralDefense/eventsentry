#!/usr/bin/env python3
#vim: sw=4:ts=4:et:cc=120

import argparse
import datetime
import json
import logging
import os
import os.path
import re
import shutil
import sys

try:
    from ace_client_lib.constants import *
    from ace_client_lib.client import Alert
except ImportError:
    sys.path.append('.')
    from ace_client_lib.constants import *
    from ace_client_lib.client import Alert

parser = argparse.ArgumentParser(description="Utility to submit ACE alerts from the command line.")
parser.add_argument('-u', '--url', required=True, dest='url', help="The submission URL to use.")
parser.add_argument('-k', '--key', required=False, default=None, dest='key', 
                    help="Override the submission key specified in the failed alerts.")
parser.add_argument('--tool', required=False, dest='tool', default='command_line',
                    help="Name of the tool or process that generated the alert.")
parser.add_argument('--tool-instance', required=False, dest='tool_instance', default='',
                    help="Instance of the tool or process that generated the alert.")
parser.add_argument('--type', required=False, dest='alert_type', default='command-line',
                    help="The type of alert being generated.")
parser.add_argument('--event-time', required=False, dest='event_time', default=None,
                    help="The time the event that caused the alert occurred.  Defaults to now.")
parser.add_argument('--description', required=False, dest='description', default='COMMAND_LINE_ALERT',
                    help="The summary text of the Alert.")
parser.add_argument('--name', required=False, dest='name', default='Command Line Alert',
                    help="The common name of the generated alert.")
parser.add_argument('--details', required=False, dest='details', default=None,
                    help="The details of the alert.  Also see --load-details and --from-stdin.")
parser.add_argument('--from-stdin', required=False, dest='from_stdin', default=False, action='store_true',
                    help="The details of the alert.  Also see --load-details and --from-stdin.")
parser.add_argument('--load-details-text', required=False, dest='details_file', default=None,
                    help="Load the details from the given plain text file.")
parser.add_argument('--load-details-json', required=False, dest='details_json', default=None,
                    help="Load the details from the given JSON file.")
parser.add_argument('--add-file', required=False, action='append', dest='attached_files', default=[],
                    help="Adds the given file as an attachment. This option can be specified more than once.")
parser.add_argument('--add-observable', nargs='*', required=False, action='append', dest='observables', default=[],
                    help="""Adds the given type and value (two arguments) as an observable. 
                            Optional arguments can be appended with the following fomart.
                            * o:time "YYYY-MM-DD HH:MM:SS"
                            * o:directive directive1,directive2,...
                            o:time specifies an alternative time of the observation.
                            o:directives adds one or more comma separated directives to the observable.
                            This option can be specified more than once.""")
parser.add_argument('--add-tag', required=False, action='append', dest='tags', default=[],
                    help="Adds the given tag to the alert.  This option can be specified more than once.")
args = parser.parse_args()

logging.basicConfig(level=logging.DEBUG)

event_time = datetime.datetime.now()
if args.event_time:
    event_time = datetime.datetime.strptime(args.event_time, event_time_format)

details = None
if args.details:
    details = args.details

if args.details_file:
    with open(args.details_file, 'r') as fp:
        details = fp.read()

if args.details_json:
    with open(args.details_json, 'r') as fp:
        details = json.load(fp)

if args.from_stdin:
    details = sys.stdin.read()

alert = Alert(
    tool=args.tool,
    tool_instance=args.tool_instance,
    alert_type=args.alert_type,
    desc=args.description,
    event_time=event_time,
    details=details,
    name=args.name)

for file_path in args.attached_files:
    alert.add_attachment_link(file_path, os.path.basename(file_path))

for o_params in args.observables[:]:
    if len(o_params) < 2:
        logging.error("--add-observable requires at least type value")
        sys.exit(1)

    o_type = o_params.pop(0)
    o_value = o_params.pop(0)
    o_time = None
    o_directives = []

    while len(o_params):
        o_opt = o_params.pop(0)
        if o_opt == 'o:time':
            o_time = o_params.pop(0)
        elif o_opt == 'o:directive':
            directive = o_params.pop(0)
            if not is_valid_directive(directive):
                logging.error("invalid directive {}".format(directive))
                sys.exit(1)

            o_directives.append(directive)

    alert.add_observable(o_type, o_value, o_time=o_time, directives=o_directives)
    
#for o_type, o_value in args.observables:
    #alert.add_observable(o_type, o_value)

for tag in args.tags:
    alert.add_tag(tag)

alert.submit(args.url, args.key)
