import hashlib
import magic
import os
import re


class File():
    def __init__(self, path):
        """ Represents a file within the event directory. """

        self.path = path

        if self.is_ace_alert():
            self.critical = True
            self.category = 'ace_alert'
        elif self.is_html():
            self.critical = True
            self.category = 'html'
        elif self.is_screenshot():
            self.critical = True
            self.category = 'screenshot'
        elif self.is_email():
            self.critical = True
            self.category = 'email'
        elif self.is_cuckoo():
            self.critical = True
            self.category = 'cuckoo'
        elif self.is_vxstream():
            self.critical = True
            self.category = 'vxstream'
        elif self.is_wildfire():
            self.critical = True
            self.category = 'wildfire'
        else:
            self.critical = False
            self.category = 'other'

        # Calculate the file's MD5 hash if it is a critical file.
        # Otherwise, leave it blank for now. It will get filled
        # in later if it is determined that the event has changed.
        if self.critical:
            self.md5 = self.calculate_md5()
        else:
            self.md5 = ''

    def __eq__(self, other):
        """ Returns True if both MD5 hashes are present and the same. """

        if self.md5 and other.md5:
            return self.md5 == other.md5

        return False

    def __hash__(self):
        """ Uses the MD5 as the hash. """

        return hash(self.md5)

    @property
    def json(self):
        """ Returns a JSON-compatible form of the file. """

        return self.__dict__

    def calculate_md5(self):
        """ Calculates the MD5 hash of the file. It returns
        the 'empty' MD5 hash if there were any exceptions. """

        try:
            md5 = hashlib.md5()
            with open(self.path, 'rb') as f:
                md5.update(f.read())

            return md5.hexdigest()
        except:
            return 'd41d8cd98f00b204e9800998ecf8427e'

    def is_ace_alert(self):
        """ Determines if the file is a valid ACE alert. """

        if 'data.json' in self.path:
            ace_data_json_pattern = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/data.json$')
            if ace_data_json_pattern.search(self.path):
                return True

        return False

    def is_email(self):
        """ Determines if the file is a valid RFC822 email. """

        if 'rfc822' in os.path.basename(self.path) and not self.path.endswith('.headers'):
            try:
                if magic.from_file(self.path, mime=True) == 'message/rfc822':
                    return True
            except:
                pass

        return False

    def is_cuckoo(self):
        """ Determines if the file is a valid Cuckoo report. """

        valid_sandbox_paths = ['cuckoo', 'vxstream', 'wildfire']

        if self.path.endswith('.json') and any(sandbox.lower() in self.path.lower() for sandbox in valid_sandbox_paths):
            if all(self.path.lower().rfind('cuckoo') >= self.path.lower().rfind(sandbox) for sandbox in valid_sandbox_paths):
                return True
        else:
            return False

    def is_vxstream(self):
        """ Determines if the file is a valid VxStream report. """

        valid_sandbox_paths = ['cuckoo', 'vxstream', 'wildfire']

        if self.path.endswith('.json') and any(sandbox.lower() in self.path.lower() for sandbox in valid_sandbox_paths):
            if all(self.path.lower().rfind('vxstream') >= self.path.lower().rfind(sandbox) for sandbox in valid_sandbox_paths):
                return True
        else:
            return False

    def is_wildfire(self):
        """ Determines if the file is a valid Wildfire report. """

        valid_sandbox_paths = ['cuckoo', 'vxstream', 'wildfire']

        if self.path.endswith('.json') and any(sandbox.lower() in self.path.lower() for sandbox in valid_sandbox_paths):
            # Ignore some extra files the Wildfire command generates.
            if not 'report.processtree_' in self.path and not 'report.network_' in self.path:
                if all(self.path.lower().rfind('wildfire') >= self.path.lower().rfind(sandbox) for sandbox in valid_sandbox_paths):
                    return True
        else:
            return False

    def is_html(self):
        """ Determines if the file is a valid HTML file.

            Instead of relying on calculating the mimetype for each file,
            which is fairly slow, we will assume that the html files have
            some common path and/or name characteristics and then verify
            using the mimetype.
        """

        maybe_html = False

        # If 'html' is in the filename...
        # NOTE: This accounts for both .html files as well as _html_ email bodies.
        if 'htm' in os.path.basename(self.path):
            maybe_html = True

        # If '.php' is in the filename...
        if '.php' in os.path.basename(self.path):
            maybe_html = True

        # If '.fpage' is in the filename...
        if '.fpage' in os.path.basename(self.path):
            return True

        # If '/crawlphish/' is in the path...
        if '/crawlphish/' in self.path:
            maybe_html = True

        # Verify the file's mimetype if we think it might be html.
        if maybe_html:
            try:
                if os.path.basename(self.path).endswith('.html'):
                    return True
                mimetype = magic.from_file(self.path, mime=True).lower()
                if 'html' in mimetype:
                    return True
            except:
                pass

        return False

    def is_screenshot(self):
        """ Determines if the file is a screenshot.

            Similar to html files, we will assume that screenshots follow a
            naming convention and always end in '.png'.
        """

        if os.path.basename(self.path).endswith('.png'):
            try:
                if magic.from_file(self.path, mime=True) == 'image/png':
                    return True
            except:
                pass

        return False
