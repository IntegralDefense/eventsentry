import ipaddress
import logging
import re
import urllib
from tld import get_fld
from urllib.parse import urlsplit
from urlfinderlib import is_valid

class Indicator:
    def __init__(self, type, value, status='New', tags=[], relationships=[]):
        """ Represents a SIP indicator. """

        self.type = type
        self.value = value
        self.status = status
        self.tags = tags
        self.relationships = relationships

        # These values are filled in by the Event class when it gathers the indicators
        # and runs them through the whitelist prior to writing the event JSON. The parsers
        # *might* pre-set the status to Whitelisted when they check whether or not things
        # like dropped files or HTTP requests are whitelisted.
        self.whitelisted = False
        if self.status == 'Whitelisted':
            self.whitelisted = True
        self.path = ''

    def __eq__(self, other):
        """ Returns True if the types and values are the same. """

        return self.type == other.type and self.value == other.value

    def __hash__(self):
        """ Uses the type and value as the hash. """

        return hash((str(self.type) + str(self.value)))

    @property
    def json(self):
        """ Returns a JSON compatible form of the indicator. """

        json = {}
        json['type'] = self.type
        json['value'] = self.value
        json['status'] = self.status
        json['tags'] = list(set(self.tags))
        json['relationships'] = list(set(self.relationships))
        json['whitelisted'] = self.whitelisted
        json['path'] = self.path

        return json

def merge_indicators(indicators):
    """ Merges a list of indicators that might have duplicates. """

    logger = logging.getLogger(__name__)
    merged = []

    for ind in indicators:

        # If this indicator (based on type+value) isn't already in the list, add it.
        if not ind in merged:
            merged.append(ind)
        # Otherwise, we need to merge the two.
        else:
            # Find the indicator in the merged list to merge with.
            for merged_ind in merged:
                if ind == merged_ind:
                    # Merge the tags.
                    merged_ind.tags = list(set(ind.tags + merged_ind.tags))

                    # Merge the relationships.
                    merged_ind.relationships = list(set(ind.relationships + merged_ind.relationships))

                    # If at least one of the indicators has the Whitelisted status, let that take precedence.
                    # Otherwise, let the New status take precedence.
                    if ind.whitelisted or merged_ind.whitelisted:
                        merged_ind.status = 'Whitelisted'
                        merged_ind.whitelisted = True
                    elif ind.status == 'New' or merged_ind.status == 'New':
                        merged_ind.status = 'New'
                        merged_ind.whitelisted = False

    return merged

def make_url_indicators(urls, tags=[]):
    """ Make indicators from a list of URLs. """
    logger = logging.getLogger(__name__)

    if isinstance(urls, str):
        urls = [urls]

    indicators = []

    for u in set(urls):
        if is_valid(u):
            parsed_url = urlsplit(u)
            url_without_query = parsed_url.scheme + '://' + parsed_url.netloc + parsed_url.path

            url_variations = set()
            url_variations.add(u)
            url_variations.add(url_without_query)

            for u in url_variations:
                """
                # If the URL is whitelisted, we want to make sure that we mark its component parts
                # (the netloc and the path/query) as Informational. We don't want to mark them as
                # Whitelisted since, for example, there can be cases where some URI paths from a
                # given domain are good and others are not. (See: dropbox.com)
                if whitelist.is_url_whitelisted(u):
                    status = 'Informational'
                else:
                    status = 'New'
                """
                status = 'New'

                # Hacky way to deal with URLs that have a username:password notation.
                user_pass_url = ''

                parsed_url = urlsplit(u)

                # First check if the netloc has a ':' in it, which indicates that
                # there is a port number specified. We need to remove that in order
                # to properly create indicators for it.
                if ':' in parsed_url.netloc:
                    netloc = parsed_url.netloc.split(':')[0]
                else:
                    netloc = parsed_url.netloc

                # Look for the edge case of the URL having a username:password notation.
                try:
                    if ':' in parsed_url.netloc and '@' in parsed_url.netloc:
                        user_pass = re.compile(r'(.*?:.*?@)').findall(parsed_url.netloc)[0]
                        user_pass_url = u.replace(user_pass, '')
                        parsed_url = urlsplit(user_pass_url)
                        netloc = parsed_url.netloc
                except:
                    pass

                # Domain/IP
                try:
                    ipaddress.ip_address(netloc)
                    indicators.append(Indicator('Address - ipv4-addr', netloc, status=status, tags=tags+['ip_in_url'], relationships=[u]))
                except ValueError:
                    indicators.append(Indicator('URI - Domain Name', netloc, status=status, tags=tags+['domain_in_url'], relationships=[u]))

                # TLD
                tld = get_fld('http://{}'.format(netloc), fail_silently=True)
                if tld:
                    indicators.append(Indicator('URI - Domain Name', tld, status=status, tags=tags, relationships=[u]))

                # Full URL
                indicators.append(Indicator('URI - URL', u, tags=tags))

                # Path
                indicators.append(Indicator('URI - Path', parsed_url.path, status=status, tags=tags, relationships=[u, parsed_url.netloc]))
                try:
                    decoded_path = urllib.parse.unquote(parsed_url.path)
                    if not decoded_path == parsed_url.path:
                        indicators.append(Indicator('URI - Path', decoded_path, status=status, tags=tags, relationships=[u, parsed_url.netloc]))
                except:
                    pass

                # Query
                indicators.append(Indicator('URI - Path', parsed_url.query, status=status, tags=tags, relationships=[u, parsed_url.netloc]))

    good_indicators = [i for i in set(indicators) if i.value]

    return good_indicators
