import ipaddress
import re
import urllib
from tld import get_fld
from urllib.parse import urlsplit
from urltools import is_valid

class Indicator:
    def __init__(self, type, value, status='New', tags=[], relationships=[]):
        """ Represents a CRITS indicator. """

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


def get_crits_status(mongo_connection, indicator):
    """ Queries the Mongo DB connection to get the indicator status. """

    try:
        if isinstance(indicator, dict):
            indicator_type = indicator['type']
            indicator_value = indicator['value']
        else:
            indicator_type = indicator.type
            indicator_value = indicator.value

        # The use of regex for a case-insensitive search really slows this down...
        result = list(mongo_connection.find('indicators', {'type': indicator_type, 'value': re.compile('^{}$'.format(re.escape(indicator_value)), re.IGNORECASE)}))
        if result:
            return result[0]['status']
        else:
            return 'New'
    except:
        return 'Unknown'


def get_crits_id(mongo_connection, indicator):
    """ Queries the Mongo DB connection to get the indicator ID. """

    try:
        if isinstance(indicator, dict):
            indicator_type = indicator['type']
            indicator_value = indicator['value']
        else:
            indicator_type = indicator.type
            indicator_value = indicator.value

        # The use of regex for a case-insensitive search really slows this down...
        result = list(mongo_connection.find('indicators', {'type': indicator_type, 'value': re.compile('^{}$'.format(re.escape(indicator_value)), re.IGNORECASE)}))
        if result:
            return result[0]['_id']
        else:
            return None
    except:
        raise


def make_url_indicators(urls, tags=[]):
    """ Make indicators from a list of URLs. """

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

                # Domain
                try:
                    ipaddress.ip_address(netloc)
                    netloc_type = 'Address - ipv4-addr'
                except:
                    netloc_type = 'URI - Domain Name'
                indicators.append(Indicator(netloc_type, netloc, status=status, tags=tags, relationships=[u]))

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

    return [i for i in set(indicators) if i.value]
