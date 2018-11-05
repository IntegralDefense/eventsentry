import base64
import configparser
import dateutil.parser
import email
import hashlib
import logging
import os
import re

from dateutil import tz
from email.header import decode_header, make_header
from urlfinderlib import find_urls
from urlfinderlib import is_valid

from lib import RegexHelpers
from lib.constants import HOME_DIR
from lib.indicator import Indicator
from lib.indicator import make_url_indicators


class EmailParser():
    def __init__(self, smtp_path, whitelist):
        # Load the config file.
        config_path = os.path.join(HOME_DIR, 'etc', 'local', 'config.ini')
        if not os.path.exists(config_path):
            raise FileNotFoundError('Unable to locate config.ini at: {}'.format(config_path))
        self.config = configparser.ConfigParser()
        self.config.read(config_path)

        # Initiate logging.
        self.logger = logging.getLogger()

        # Save the whitelist.
        self.whitelist = whitelist

        # Items we parse out of the email.
        self.ace_url = ''
        self.attachments = []
        self.body = ''
        self.cc_addresses = []
        self.envelope_from = ''
        self.envelope_to = ''
        self.from_address = ''
        self.headers = ''
        self.html = ''
        self.indicators = []
        self.message_id = ''
        self.original_recipient = ''
        self.path = smtp_path
        self.received = ''
        self.received_time = ''
        self.remediated = False
        self.reply_to = ''
        self.return_path = ''
        self.screenshots = []
        self.subject = ''
        self.subject_decoded = ''
        self.to_addresses = []
        self.urls = []
        self.x_auth_id = ''
        self.x_mailer = ''
        self.x_original_sender = ''
        self.x_originating_ip = ''
        self.x_sender = ''
        self.x_sender_id = ''
        self.x_sender_ip = ''

        # Build the URL to the ACE alert.
        ace_uuid_pattern = re.compile(r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})')
        match = ace_uuid_pattern.search(self.path)
        if match:
            self.ace_url = '{}{}'.format(self.config.get('production', 'ace_alert_url', fallback=None), match.group(1))

        with open(self.path, encoding='utf-8', errors='ignore') as s:
            smtp_stream = s.read().splitlines()

        # Locate any screenshots for this email.
        email_dir = os.path.dirname(self.path)
        files = os.listdir(email_dir)
        for f in files:
            if 'text_html' in f and f.endswith('.png') and not f.startswith('email_screenshot'):
                self.logger.debug('Found email screenshot: {}'.format(os.path.join(email_dir, f)))
                self.screenshots.append(os.path.join(email_dir, f))

        # Find the envelope from/to addresses. This will only work if given an
        # "smtp.stream" file, since otherwise the SMTP commands will not exist.
        envelope_address_pattern = re.compile(r'.*<(.*)>.*')
        for line in smtp_stream:
            if line.startswith('MAIL FROM:'):
                try:
                    self.envelope_from = envelope_address_pattern.match(line).group(1)
                except:
                    self.logger.exception('Unable to parse envelope from.')
            if line.startswith('RCPT TO:'):
                try:
                    self.envelope_to = envelope_address_pattern.match(line).group(1)
                except:
                    self.logger.exception('Unable to parse envelope to.')

        # Just in case we are dealing with an "smtp.stream" file that still has
        # the SMTP commands above the actual e-mail, we need to strip those out.
        # This will remove all lines prior to the Received: headers so that the
        # email.parser can properly parse out the e-mail. If we were given an
        # "smtp.email" type of file with the SMTP commands already removed, this
        # should not affect anything. This is legacy code at this point.
        while not smtp_stream[0].startswith('Received:'):
            smtp_stream.pop(0)

        # Join the header lines into a single string.
        email_text = '\n'.join(smtp_stream)

        # Create the e-mail object.
        email_obj = email.message_from_string(email_text)

        # We want to try and parse an embedded/attached e-mail if there is one.
        # Walk the full e-mail's parts.
        for part in email_obj.walk():
            # Continue if the part looks like a valid e-mail.
            if part.get_content_type() == 'message/rfc822':
                # Split the part lines into a list.
                part_text = str(part).splitlines()
                if any('Received:' in line for line in part_text):
                    # Make sure our part starts with the Received: headers.
                    while not part_text[0].startswith('Received:'):
                        part_text.pop(0)
                    part_text = '\n'.join(part_text)

                    # Make the new e-mail object.
                    email_obj = email.message_from_string(part_text)

        # Parse the e-mail object for its content.
        parsed_email = self._parse_content(email_obj)

        # Now that we have the e-mail object, parse out some of the interesting parts.
        self.headers = self._get_all_headers_string(email_obj)
        self.received = self.get_header(email_obj, 'received')

        # Get the e-mail's plaintext body, HTML body, and the visible text from the HTML.
        self.body = parsed_email['body']
        self.html = parsed_email['html']

        # Get any e-mail attachments.
        self.attachments = parsed_email['attachments']

        # From address
        try:
            self.from_address = self._get_address_list(email_obj, 'from')[0][1]
            self.indicators.append(Indicator('Email - Address', self.from_address, tags=['from_address']))
        except:
            pass

        # From domain
        try:
            self.indicators.append(Indicator('URI - Domain Name', self.from_address.split('@')[1], tags=['from_domain']))
        except:
            pass

        # Reply-To address
        try:
            self.reply_to = self._get_address_list(email_obj, 'reply-to')[0][1]
            self.indicators.append(Indicator('Email - Address', self.reply_to, tags=['reply_to']))
        except:
            pass

        # X-Sender address
        try:
            self.x_sender = self._get_address_list(email_obj, 'X-Sender')[0][1]
            self.indicators.append(Indicator('Email - Address', self.x_sender, tags=['x_sender']))
        except:
            pass

        # X-Sender-Id address
        try:
            self.x_sender_id = self._get_address_list(email_obj, 'X-Sender-Id')[0][1]
            self.indicators.append(Indicator('Email - Address', self.x_sender_id, tags=['x_sender_id']))
        except:
            pass

        # X-Auth-Id address
        try:
            self.x_auth_id = self._get_address_list(email_obj, 'X-Auth-ID')[0][1]
            self.indicators.append(Indicator('Email - Address', self.x_auth_id, tags=['x_auth_id']))
        except:
            pass

        # Return-Path address
        try:
            self.return_path = self._get_address_list(email_obj, 'return_path')[0][1]
            self.indicators.append(Indicator('Email - Address', self.return_path, tags=['return_path']))
        except:
            pass

        # X-MS-Exchange-Organization-OriginalEnvelopeRecipients address
        try:
            self.original_recipient = self._get_address_list(email_obj, 'X-MS-Exchange-Organization-OriginalEnvelopeRecipients')[0][1].lower()
            self.indicators.append(Indicator('Email - Address', self.original_recipient, status='Informational', tags=['original_recipient']))
        except:
            pass
        # If the original_recipient was not found, check if this is a POTENTIAL PHISH e-mail and use the from address.
        if not self.original_recipient and 'Subject: [POTENTIAL PHISH]' in email_text:
            try:
                temp_email_obj = email.message_from_string(email_text)
                self.original_recipient = self._get_address_list(temp_email_obj, 'from')[0][1]
                self.indicators.append(Indicator('Email - Address', self.original_recipient, status='Informational', tags=['original_recipient']))
            except:
                self.logger.exception('Error parsing original recipient from POTENTIAL PHISH e-mail.')

        # Subject
        try:
            self.subject = ''.join(self.get_header(email_obj, 'subject')[0].splitlines())
            self.indicators.append(Indicator('Email - Subject', self.subject))
        except:
            pass

        # Decoded subject
        try:
            self.subject_decoded = ''.join(str(make_header(decode_header(self.get_header(email_obj, 'subject')[0]))).splitlines())
            self.indicators.append(Indicator('Email - Subject', self.subject_decoded))
        except:
            pass

        # To addresses
        self.to_addresses = [x[1].lower() for x in self._get_address_list(email_obj, 'to')]

        # CC addresses
        self.cc_addresses = [x[1].lower() for x in self._get_address_list(email_obj, 'cc')]

        # Message-Id
        try:
            self.message_id = self.get_header(email_obj, 'message-id')[0]
            self.indicators.append(Indicator('Email Message ID', self.message_id, status='Informational'))
        except:
            pass

        # X-Mailer
        try:
            self.x_mailer = self.get_header(email_obj, 'x-mailer')[0]
            self.indicators.append(Indicator('Email - Xmailer', self.x_mailer, status='Informational'))
        except:
            pass

        # X-Original-Sender address
        try:
            self.x_original_sender = self.get_header(email_obj, 'x-original-sender')[0]
            self.indicators.append(Indicator('Email - Address', self.x_original_sender, tags=['x_original_sender']))
        except:
            pass

        # X-Originating-Ip
        try:
            x_originating_ip = self.get_header(email_obj, 'x-originating-ip')[0]
            # Sometimes this field is in the form: [1.1.1.1]
            # Make sure we remove any non-IP characters.
            ip = RegexHelpers.find_ip_addresses(x_originating_ip)
            if ip:
                self.x_originating_ip = ip[0]
                self.indicators.append(Indicator('Address - ipv4-addr', self.x_originating_ip, tags=['x_originating_ip']))
        except:
            pass

        # X-Sender-Ip
        try:
            x_sender_ip = self.get_header(email_obj, 'x-sender-ip')[0]
            # Make sure like the X-Originating-IP that we only
            # get the IP address and no other characters.
            ip = RegexHelpers.find_ip_addresses(x_sender_ip)
            if ip:
                self.x_sender_ip = ip[0]
                self.indicators.append(Indicator('Address - ipv4-addr', self.x_sender_ip, tags=['x_sender_ip']))
        except:
            pass

        self.received_time = self._get_received_time(email_obj)

        # Find any URLs in the plaintext body.
        text_urls = find_urls(self.body)

        # Find any URLs in the HTML body.
        html_urls = find_urls(self.html)

        # Get any strings URLs.
        strings_urls = []
        """
        for file in self.attachments:
            try:
                strings_urls += file['strings_urls']
            except:
                pass
        """

        # Try and remove any URLs that look like partial versions of other URLs.
        all_urls = text_urls + html_urls + strings_urls
        unique_urls = set()
        for u in all_urls:
            if not any(other_url.startswith(u) and other_url != u for other_url in all_urls):
                unique_urls.add(u)

        # Get rid of any invalid URLs.
        self.urls = [u for u in unique_urls if is_valid(u)]

        # Make indicators for the URLs.
        self.indicators += make_url_indicators(self.urls)

        # Get rid of any invalid and duplicate indicators.
        self.indicators = [i for i in set(self.indicators) if i.value]

        # Add any extra tags to each indicator.
        for i in self.indicators:
            i.tags.append('phish')

    def __eq__(self, other):
        """ Returns True if the headers are equal. """

        return self.headers.lower() == other.headers.lower()

    def __hash__(self):
        """ Use the headers as the hash. """

        return hash((self.headers.lower()))

    @property
    def json(self):
        """ Return a JSON compatible view of the email. """

        json = {}
        json['ace_url'] = self.ace_url
        json['attachments'] = self.attachments
        json['body'] = self.body
        json['cc_addresses'] = self.cc_addresses
        json['envelope_from'] = self.envelope_from
        json['envelope_to'] = self.envelope_to
        json['from_address'] = self.from_address
        json['headers'] = self.headers
        json['html'] = self.html
        json['message_id'] = self.message_id
        json['original_recipient'] = self.original_recipient
        json['path'] = self.path
        json['received'] = self.received
        json['received_time'] = self.received_time
        json['remediated'] = self.remediated
        json['reply_to'] = self.reply_to
        json['return_path'] = self.return_path
        json['screenshots'] = self.screenshots
        json['subject'] = self.subject
        json['subject_decoded'] = self.subject_decoded
        json['to_addresses'] = self.to_addresses
        json['urls'] = self.urls
        json['x_auth_id'] = self.x_auth_id
        json['x_mailer'] = self.x_mailer
        json['x_original_sender'] = self.x_original_sender
        json['x_originating_ip'] = self.x_originating_ip
        json['x_sender'] = self.x_sender
        json['x_sender_id'] = self.x_sender_id
        json['x_sender_ip'] = self.x_sender_ip

        return json

    def get_header(self, email_obj, header_name):
        return email_obj.get_all(header_name, [])

    def _get_all_headers_string(self, email_obj):
        header_string = ''

        try:
            bad_headers = self.config.get('production', 'bad_headers', fallback=[]).split(',')
        except:
            bad_headers = []

        for header in email_obj.items():
            if not any(bad_header in header[0] for bad_header in bad_headers):
                header_string += ': '.join(header) + '\n'

        return header_string

    def _get_address_list(self, email_obj, header_name):
        header = email_obj.get_all(header_name, [])
        return email.utils.getaddresses(header)

    def _get_received_time(self, email_obj):
        header=email_obj.get_all('received', [])
        last_received_lines = header[0]

        received_time_pattern = re.compile(r'[A-Z][a-z]{2,3},\s+\d+\s+[A-Z][a-z]{2,3}\s+[0-9]{4}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\s*(\+\d+|\-\d+)*')
        last_received_time = re.search(received_time_pattern, last_received_lines)

        if last_received_time:
            datetime_obj = dateutil.parser.parse(last_received_time.group(0), ignoretz=False)
            localtime = dateutil.tz.tzlocal()
            try:
                localtime_string = str(datetime_obj.astimezone(localtime))
            except ValueError:
                localtime_string = str(datetime_obj)
            return localtime_string
        else:
            return ''

    def _get_received_for_address(self, email_obj):
        received_header = email_obj.get_all('received', [])
        receivedfor_info = email.utils.getaddresses(received_header)
        for tup in receivedfor_info:
            if 'for' in tup[0] and '@' in tup[1]:
                return tup[1]
        return None

    def _get_charset(self, obj, default='ascii'):
        if obj.get_content_charset():
            return obj.get_content_charset()

        if obj.get_charset():
            return obj.get_charset()

        return default

    # Adapted from: https://www.ianlewis.org/en/parsing-email-attachments-python
    def _parse_content(self, email_obj):
        attachments = []
        body = ''
        html = ''
        for part in email_obj.walk():
            charset = self._get_charset(part, self._get_charset(email_obj))
            attachment = self._parse_attachment(part, charset)
            # Only add the attachment to the list if we were able to get the MD5.
            if attachment and attachment['md5']:
                attachments.append(attachment)
            elif part.get_content_type() == 'text/plain':
                body += part.get_payload(decode=True).decode(charset, errors='ignore')
            elif part.get_content_type() == 'text/html':
                html += part.get_payload(decode=True).decode(charset, errors='ignore')
        return {
            'body' : body,
            'html' : html,
            'attachments': attachments
        }

    # Adapted from: https://www.ianlewis.org/en/parsing-email-attachments-python
    def _parse_attachment(self, message_part, charset):
        part_items = message_part.items()
        for tup in part_items:
            for value in tup:
                if 'attachment' in value:
                    file_data = message_part.get_payload()

                    attachment_dict = {}
                    if message_part.get('Content-Transfer-Encoding', None) == 'base64':
                        file_data_b64 = file_data.replace('\n', '')
                        # For some reason, sometimes the attachments don't have the proper
                        # padding. Add a couple "==" on the end for good measure. This doesn't
                        # seem to harm correctly encoded attachments.
                        file_data_decoded = base64.b64decode(file_data_b64 + '==')

                        # Try and get strings out of the attachment.
                        strings_list = RegexHelpers.find_strings(file_data_decoded)
                        strings = ' '.join(strings_list)

                        # Look for any URLs that were in the strings.
                        strings_urls = find_urls(strings)
                        attachment_dict['strings_urls'] = strings_urls

                    elif message_part.get_content_type() == 'text/html':
                        file_data_decoded = message_part.get_payload(decode=True).decode(charset).encode('utf-8')
                    else:
                        file_data_decoded = file_data

                    try:
                        md5_hasher = hashlib.md5()
                        md5_hasher.update(file_data_decoded)
                        md5_hash = md5_hasher.hexdigest()
                    except TypeError:
                        md5_hash = ''

                    try:
                        sha256_hasher = hashlib.sha256()
                        sha256_hasher.update(file_data_decoded)
                        sha256_hash = sha256_hasher.hexdigest()
                    except TypeError:
                        sha256_hash = ''

                    attachment_dict['content_type'] = message_part.get_content_type()
                    attachment_dict['size'] = len(file_data_decoded)
                    attachment_dict['md5'] = md5_hash
                    attachment_dict['sha256'] = sha256_hash
                    attachment_dict['name'] = ''
                    attachment_dict['create_date'] = ''
                    attachment_dict['mod_date'] = ''
                    attachment_dict['read_date'] = ''

                    # Find the attachment name. Normally this follows a specific format
                    # and is called 'filename=' but recently I've seen some that are in
                    # different locations are are just called 'name='... Hence removing
                    # old code and replacing with a regex statement to account for either
                    # name in any location in the message part.
                    attachment_name_pattern = re.compile(r'(file)?name="?([^"]+)"?')
                    for tup in part_items:
                        for item in tup:
                            item_lines = item.splitlines()
                            for item_line in item_lines:
                                attachment_name = attachment_name_pattern.search(item_line)
                                if attachment_name:
                                    attachment_dict['name'] = RegexHelpers.decode_utf_b64_string(attachment_name.groups()[1])
                                    if attachment_dict['name'].endswith(';'):
                                        attachment_dict['name'] = attachment_dict['name'][:-1]
                    
                    # Make the attachment indicators.
                    self.indicators.append(Indicator('Windows - FileName', attachment_dict['name'], tags=['attachment']))
                    self.indicators.append(Indicator('Hash - MD5', attachment_dict['md5'], tags=['attachment']))
                    self.indicators.append(Indicator('Hash - SHA256', attachment_dict['sha256'], tags=['attachment']))

                    return attachment_dict

        return None
