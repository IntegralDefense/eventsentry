# vim: sw=4:ts=4:et

import datetime
import json
import logging
import os.path
import shutil
import uuid

import requests

# the expected format of the event_time of an alert
event_time_format = '%Y-%m-%d %H:%M:%S'

# current protocol version
# update this protocol number when you update the protocol
# this is used by the server.py code in saq to select which functions to handle the request
PROTOCOL_VERSION = "1.5"

class AlertSubmitException(Exception):
    pass

# utility class to translate custom objects into JSON
class _JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime(event_time_format)
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, Attachment):
            return obj.relative_storage_path
        else:
            return super(_JSONEncoder, self).default(obj)

class Attachment(object):
    def __init__(self, source_path, relative_storage_path):
        self.source_path = source_path
        self.relative_storage_path = relative_storage_path

    def __str__(self):
        return "Attachment(from {} to {})".format(self.source_path, self.relative_storage_path)

class Alert(object):

    KEY_ID = 'id'
    KEY_UUID = 'uuid'
    KEY_TOOL = 'tool'
    KEY_TOOL_INSTANCE = 'tool_instance'
    KEY_TYPE = 'type'
    KEY_DESCRIPTION = 'description'
    KEY_EVENT_TIME = 'event_time'
    KEY_DETAILS = 'details'
    KEY_OBSERVABLES = 'observables'
    KEY_TAGS = 'tags'
    KEY_ATTACHMENTS = 'attachments'
    KEY_NAME = 'name'
    KEY_COMPANY_NAME = 'company_name'
    KEY_COMPANY_ID = 'company_id'

    def __init__(self, 
        tool=None, 
        tool_instance=None, 
        alert_type=None, 
        desc=None, 
        event_time=None, 
        details=None,
        name=None,
        company_name=None,
        company_id=None):

        self._event_time = None
            
        self.uuid = str(uuid.uuid4())
        self.tool = tool
        self.tool_instance = tool_instance
        self.alert_type = alert_type
        self.description = desc
        self.event_time = event_time
        self.details = details

        self.attachments = []
        self.observables = {}
        self.tags = set()
        self.name = name
        self.company_name = company_name
        self.company_id = company_id

    def __str__(self):
        return "Alert({})".format(self.uuid)

    @property
    def network_json(self):
        return {
            Alert.KEY_UUID: self.uuid,
            Alert.KEY_TOOL: self.tool,
            Alert.KEY_TOOL_INSTANCE: self.tool_instance,
            Alert.KEY_TYPE: self.alert_type,
            Alert.KEY_DESCRIPTION: self.description,
            Alert.KEY_EVENT_TIME: self.event_time,
            Alert.KEY_DETAILS: self.details,
            Alert.KEY_OBSERVABLES: self.observables,
            Alert.KEY_TAGS: self.tags,
            Alert.KEY_ATTACHMENTS: self.attachments,
            Alert.KEY_NAME: self.name,
            Alert.KEY_COMPANY_NAME: self.company_name,
            Alert.KEY_COMPANY_ID: self.company_id,
        }

    @network_json.setter
    def network_json(self, alert_json):
        self.uuid = alert_json[Alert.KEY_UUID]
        self.tool = alert_json[Alert.KEY_TOOL]
        self.tool_instance = alert_json[Alert.KEY_TOOL_INSTANCE]
        self.alert_type = alert_json[Alert.KEY_TYPE]
        self.description = alert_json[Alert.KEY_DESCRIPTION]
        self.event_time = alert_json[Alert.KEY_EVENT_TIME]
        self.details = alert_json[Alert.KEY_DETAILS]
        self.observables = alert_json[Alert.KEY_OBSERVABLES]
        self.tags = alert_json[Alert.KEY_TAGS]
        self.attachments = alert_json[Alert.KEY_ATTACHMENTS]
        if Alert.KEY_NAME in alert_json:
            self.name = alert_json[Alert.KEY_NAME]
        if Alert.KEY_COMPANY_NAME in alert_json:
            self.company_name = alert_json[Alert.KEY_COMPANY_NAME]
        if Alert.KEY_COMPANY_ID in alert_json:
            self.company_id = alert_json[Alert.KEY_COMPANY_ID]

    @property
    def event_time(self):
        #"""YYYY-MM-DD HH:MM:SS UTC <-- the time the event occurred, NOT when SAQ received it."""
        return self._event_time

    @event_time.setter
    def event_time(self, value):
        if value is None:
            self._event_time = None
        elif isinstance(value, datetime.datetime):
            self._event_time = value.strftime(event_time_format) 
        elif isinstance(value, str):
            self._event_time = value
        else:
            raise ValueError("event_time must be a datetime.datetime object or a string in the format %Y-%m-%d %H:%M:%S you passed {}".format(type(value).__name__))

    @property
    def event_time_datetime(self):
        """Return a datetime.datetime representation of self.event_time."""
        if self._event_time is None:
            return None

        return datetime.datetime.strptime(self._event_time, event_time_format)

    # (this is a drop-in replacement function)
    def add_attachment_link(self, source_path, relative_storage_path):
        self.attachments.append(Attachment(source_path, relative_storage_path))

    # (this is a drop-in replacement function)
    def add_observable(self, o_type, o_value, o_time=None, is_suspect=False, directives=[]):
        if o_type not in self.observables:
            self.observables[o_type] = []

        self.observables[o_type].append((o_value, o_time, is_suspect, directives))
        logging.debug("added observable type {} value {} time {} suspect {} directives {} to {}".format(
            o_type, o_value, o_time, is_suspect, directives, self))

    # (this is a drop-in replacement function)
    def add_tag(self, tag):
        self.tags.add(tag)
        logging.debug("added tag {} to {}".format(tag, self))

    def load_saved_alert(self, path):
        """Loads an alert that was saved when a call to submit() failed.  Returns a tuple of (uri, key) which was used to submit the alert when it failed."""
        saved_json = {}
        with open(path, 'r') as fp:
            saved_json = json.load(fp)

        # this will rebuild the Alert object
        self.network_json = saved_json

        # replace the paths with Attachment objects that contain the source path (full path to the file) and the relative path
        self.attachments = [Attachment(os.path.join(os.path.dirname(path), x), x) for x in self.attachments]

        # extract the uri and key that was used last time to submit the alert
        uri = saved_json['uri']
        key = saved_json['key']

        return (uri, key)

    # (this is a drop-in replacement function)
    def submit(self, uri, key, fail_dir=".saq_alerts", save_on_fail=True):
        """Submits this Alert to ACE for analysis to the given URI with the given key.  Returns tuple(http_status_code, http_text)."""
        assert isinstance(uri, str)
        assert len(uri) > 0

        # make sure we're not using the proxy
        if 'http_proxy' in os.environ:
            logging.warning("removing proxy setting http_proxy from environment variables")
            del os.environ['http_proxy']

        try:
            # append the attachments to the POST
            _file_info = []
            for attachment in self.attachments:
                # when the alert is created new it will have these Attachment objects in here
                if isinstance(attachment, Attachment):
                    _file_info.append(('data', (attachment.relative_storage_path, open(attachment.source_path, 'rb'), 'application/octet-stream')))

            logging.info("submitting alert {} to {}".format(self, uri))
            r = requests.post(
                uri,
                data = { 
                    'alert': json.dumps(self.network_json, cls=_JSONEncoder, sort_keys=True),
                    'key': key,
                    'protocol_version': PROTOCOL_VERSION },
                files = _file_info)
            
            if r.status_code != 200:
                logging.error("alert submission failed: {} ({})".format(
                    r.status_code, r.reason))
                raise AlertSubmitException()

            return (r.status_code, r.text)

        except Exception as submission_error:

            logging.warning("unable to submit alert {}: {} (attempting to save alert to {})".format(
                self, str(submission_error), fail_dir))

            if not save_on_fail:
                raise submission_error

            if fail_dir is None:
                logging.error("fail_dir is set to None")
                raise submission_error

            dest_dir = os.path.join(fail_dir, self.uuid)
            if not os.path.isdir(dest_dir):
                try:
                    os.makedirs(dest_dir)
                except Exception as e:
                    logging.error("unable to create directory {} to save alert {}: {}".format(
                        dest_dir, self, str(e)))
    
                    raise e

            # save the attachments
            for attachment in self.attachments:
                src = None
                dst = dest_dir

                try:
                    # create the containing directory of the attachment if it does not already exist
                    src = attachment.source_path
                    dst = os.path.dirname(os.path.join(dest_dir, attachment.relative_storage_path))
                    if not os.path.isdir(dst):
                        os.makedirs(dst)
                except Exception as e:
                    logging.error("unable to create storage directory {} for alert {}: {}".format(dst, self, str(e)))

                # destination path of the file
                dst_path = os.path.join(dst, os.path.basename(src))

                try:
                    shutil.copy2(src, dst_path)
                except Exception as e:
                    logging.error("unable to copy attachment from {} to {}: {}".format(src, dst_path, str(e)))
                    continue

            # get the json
            alert_json = self.network_json

            # we also include the url and submission key in the failed alert so that we can submit them later
            alert_json['uri'] = uri
            alert_json['key'] = key

            # to write it out to the filesystem
            with open(os.path.join(dest_dir, 'data.json'), 'w') as fp:  
                json.dump(alert_json, fp, cls=_JSONEncoder, sort_keys=True)

            logging.debug("saved alert {} to {}".format(self, dest_dir))
            raise submission_error

        return (500, "")
