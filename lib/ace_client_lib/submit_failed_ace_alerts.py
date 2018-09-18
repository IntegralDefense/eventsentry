#!/usr/bin/env python3
#vim: sw=4:ts=4:et

import argparse
import logging
import os
import os.path
import shutil
import sys
import re

try:
    from ace_client_lib.client import Alert
except ImportError:
    sys.path.append('.')
    from ace_client_lib.client import Alert

parser = argparse.ArgumentParser(description="Utility to re-submit failed SAQ alert submissions.")
parser.add_argument('-d', '--dir', required=False, default='.saq_alerts', dest='dir',
    help="The directory that contains the failed alerts.  Defaults to .saq_alerts")
parser.add_argument('-u', '--url', required=False, default=None, dest='url',
    help="Override the submission url specified in the failed alerts.")
parser.add_argument('-k', '--key', required=False, default=None, dest='key',
    help="Override the submission key specified in the failed alerts.")
parser.add_argument('-n', '--no-delete', required=False, action='store_true', default=False, dest='no_delete',
    help="Do not delete alerts that were successfully submitted (debugging option.)")
args = parser.parse_args()

logging.basicConfig(level=logging.DEBUG)

if not os.path.isdir(args.dir):
    logging.error("failed alerts directory {0} does not exist or is not a directory".format(args.dir))
    sys.exit(1)

# each subdirectory in this directory with a name matching the uuid regex is considered to be an alert
for subdir in os.listdir(args.dir):

    # example: 9b566e52-57c8-4340-8fc0-51f1d713199d
    if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', subdir):
        continue

    subdir = os.path.join(args.dir, subdir)

    # load the alert
    alert_path = os.path.join(subdir, 'data.json')

    alert = Alert()
    url = None
    key = None

    try:
        url, key = alert.load_saved_alert(alert_path)
    except Exception as e:
        logging.error("unable to load alert from {0}: {1}".format(alert_path, str(e)))
        continue

    if args.url is not None:
        url = args.url

    if args.key is not None:
        key = args.key

    try:
        alert.submit(url, key, save_on_fail=False)
    except Exception as e:
        logging.error("unable to submit alert {0}: {1}".format(alert, str(e)))
        continue

    if args.no_delete:
        continue

    try:
        shutil.rmtree(subdir)
    except Exception as e:
        logging.error("unable to delete directory {0}: {1}".format(subdir, str(e)))

