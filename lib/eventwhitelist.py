import ipaddress
import logging
import os
import re
from urllib.parse import urlsplit

from critswhitelist import CritsWhitelist
from urlfinderlib import is_valid


class EventWhitelist(CritsWhitelist):
    def __init__(self, whitelist_tags=['whitelist:e2w'], mongo_connection=None, mongo_uri=None, mongo_db=None, urlshortener_tags=['urlshortener:e2w']):
        super().__init__(whitelist_tags=whitelist_tags, mongo_connection=mongo_connection, mongo_uri=mongo_uri, mongo_db=mongo_db, urlshortener_tags=urlshortener_tags)

    """
    #
    # EVENT SPECIFIC WHITELIST
    #
    """

    def is_contacted_host_whitelisted(self, contacted_host):
        """ Returns True if the contacted host IP address is whitelisted. """
        """ {'ipv4': ipv4, 'port': port, 'protocol': protocol, 'location': location, 'associated_domains': associated_domains} """

        # First check if the host was already cached.
        if self._is_cached_whitelisted(contacted_host['ipv4']):
            return True
        if self._is_cached_nonwhitelisted(contacted_host['ipv4']):
            return False

        try:
            return self.is_ip_whitelisted(contacted_host['ipv4'])
        except:
            return True

    def is_dropped_file_whitelisted(self, dropped_file):
        """ Returns True if any of the parts of the dropped file are whitelisted. """
        """ {'filename': filename, 'path': path, 'size': size, 'type': type, 'md5': md5, 'sha1': sha1, 'sha256': sha256, 'sha512': sha512, 'ssdeep': ssdeep} """

        # First check if the file was already cached. Unlike the other whitelist checks, we
        # do NOT want to check if it was cached as nonwhitelisted. This is because a file
        # could have a nonwhitelisted file name yet have a whitelisted path or hash.
        if dropped_file['filename']:
            if self._is_cached_whitelisted(dropped_file['filename']):
                return True
        if dropped_file['path']:
            if self._is_cached_whitelisted(dropped_file['path']):
                return True
        if dropped_file['md5']:
            if self._is_cached_whitelisted(dropped_file['md5']):
                return True
        if dropped_file['sha1']:
            if self._is_cached_whitelisted(dropped_file['sha1']):
                return True
        if dropped_file['sha256']:
            if self._is_cached_whitelisted(dropped_file['sha256']):
                return True
        if dropped_file['sha512']:
            if self._is_cached_whitelisted(dropped_file['sha512']):
                return True
        if dropped_file['ssdeep']:
            if self._is_cached_whitelisted(dropped_file['ssdeep']):
                return True

        # Check the file name
        if dropped_file['filename']:
            if self.is_file_name_whitelisted(dropped_file['filename']):
                return True

        # Check the file path
        if dropped_file['path']:
            if self.is_file_path_whitelisted(dropped_file['path']):
                return True

        # Check the MD5
        if dropped_file['md5']:
            if self.is_md5_whitelisted(dropped_file['md5']):
                return True

        # Check the SHA1
        if dropped_file['sha1']:
            if self.is_sha1_whitelisted(dropped_file['sha1']):
                return True

        # Check the SHA256
        if dropped_file['sha256']:
            if self.is_sha256_whitelisted(dropped_file['sha256']):
                return True

        # Check the SHA512
        if dropped_file['sha512']:
            if self.is_sha512_whitelisted(dropped_file['sha512']):
                return True

        # Check the SSDEEP
        if dropped_file['ssdeep']:
            if self.is_ssdeep_whitelisted(dropped_file['ssdeep']):
                return True

        return False

    def is_http_request_whitelisted(self, http_request):
        """ Returns True if any of the parts of the HTTP request are whitelisted. """
        """ {'host': host, 'port': port, 'uri': uri, 'method': method, 'user_agent': user_agent} """

        # First check if the request was already cached. Unlike the other whitelist checks, we
        # do NOT want to check if it was cached as nonwhitelisted. This is because a request
        # could have a nonwhitelisted host yet have a whitelisted URI path.
        if self._is_cached_whitelisted(http_request['host']):
            return True
        if self._is_cached_whitelisted(http_request['uri']):
            return True

        # Check the host. Check if it is an IP address.
        try:
            ipaddress.ip_address(http_request['host'])
            if self.is_ip_whitelisted(http_request['host']):
                return True
        # If we got an exception, it must be a domain name.
        except:
            if self.is_domain_whitelisted(http_request['host']):
                return True

        # Check the URI path.
        if http_request['uri']:
            if self.is_uri_path_whitelisted(http_request['uri']):
                return True

        return False

    def is_dns_request_whitelisted(self, dns_request):
        """ Returns True if any of the parts of the DNS request are whitelisted. """
        """ {'request': request, 'type': type, 'answer': answer, 'answer_type': answer_type} """

        # First check if the request was already cached. Unlike the other whitelist checks, we
        # do NOT want to check if it was cached as nonwhitelisted. This is because a request
        # could have a nonwhitelisted host yet have a whitelisted answer.
        if self._is_cached_whitelisted(dns_request['request']):
            return True
        if self._is_cached_whitelisted(dns_request['answer']):
            return True

        # Check the requested domain.
        if self.is_domain_whitelisted(dns_request['request']):
            return True

        # Check the answer. Check if it is an IP address.
        try:
            ipaddress.ip_address(dns_request['answer'])
            if self.is_ip_whitelisted(dns_request['answer']):
                return True
        # If we got an exception, it must be a domain name.
        except:
            if self.is_domain_whitelisted(dns_request['answer']):
                return True

        return False

    def is_indicator_whitelisted(self, indicator):
        """
        Returns True if the indicator is whitelisted. It will ignore any indicators
        that already have their status set to Informational or Whitelisted, as these
        have been handled by the various parsers. (Ex: sandbox dropped files)

        Types of indicators created in events:

        Address - ipv4-addr
        Email - Address
        Email - Subject
        Email - Xmailer (Benign)
        Email Message ID (Benign)
        Hash - MD5
        Hash - SHA1
        Hash - SHA256
        Hash - SSDEEP
        URI - Domain Name
        URI - Path
        URI - URL
        Windows - FileName
        """

        # This lets us accept Indicator objects as well as their JSON form.
        if not isinstance(indicator, dict):
            indicator = indicator.json
            """
            indicator = {'type': indicator.type, 'value': indicator.value,
                         'relationships': indicator.relationships, 'status': indicator.status}
            """

        if indicator['status'] == 'Whitelisted':
            return True
        #elif indicator.status == 'Informational':
        #    return False
        else:
            if indicator['type'] == 'Address - ipv4-addr':
                return self.is_ip_whitelisted(indicator['value'])
            elif indicator['type'] == 'Email - Address':
                return self.is_email_address_whitelisted(indicator['value'])
            elif indicator['type'] == 'Email - Subject':
                return self.is_email_subject_whitelisted(indicator['value'])
            elif indicator['type'] == 'Email - Xmailer':
                return False
            elif indicator['type'] == 'Email Message ID':
                return False
            elif indicator['type'] == 'Hash - MD5':
                return self.is_md5_whitelisted(indicator['value'])
            elif indicator['type'] == 'Hash - SHA1':
                return self.is_sha1_whitelisted(indicator['value'])
            elif indicator['type'] == 'Hash - SHA256':
                return self.is_sha256_whitelisted(indicator['value'])
            elif indicator['type'] == 'Hash - SSDEEP':
                return self.is_ssdeep_whitelisted(indicator['value'])
            elif indicator['type'] == 'URI - Domain Name':
                return self.is_domain_whitelisted(indicator['value'])
            elif indicator['type'] == 'URI - Path':
                return self.is_uri_path_whitelisted(indicator['value'], relationships=indicator['relationships'])
            elif indicator['type'] == 'URI - URL':
                return self.is_url_whitelisted(indicator['value'])
            elif indicator['type'] == 'Windows - FileName':
                return self.is_file_name_whitelisted(indicator['value'])
            else:
                self.logger.warning('Unknown indicator type for whitelist: {}'.format(indicator['type']))
                return False
