import base64
import configparser
import ipaddress
import json
import logging
import os
import re
from urlfinderlib import find_urls
from urlfinderlib import is_valid

from lib.indicator import Indicator
from lib.indicator import make_url_indicators
from lib.constants import HOME_DIR


class BaseSandboxParser():
    def __init__(self, json_path=None):
        """ Initialize the parsed sandbox report. """

        # Load the config file.
        config_path = os.path.join(HOME_DIR, 'etc', 'local', 'config.ini')
        if not os.path.exists(config_path):
            raise FileNotFoundError('Unable to locate config.ini at: {}'.format(config_path))
        self.config = configparser.ConfigParser()
        self.config.read(config_path)

        # Initiate logging.
        self.logger = logging.getLogger()

        # Check if we are verifying requests.
        if self.config['production']['verify_requests'].lower() == 'true':
            self.requests_verify = True

            # Now check if we want to use a custom CA cert to do so.
            if 'verify_requests_cert' in self.config['production']:
                self.requests_verify = self.config['production']['verify_requests_cert']
        else:
            self.requests_verify = False

        # Dedup the dropped files. Dropped files are harder to whitelist, so want to limit them to
        # only certain file extensions or file types that we really care about.
        self.good_dropped_file_names = self.config['production']['dropped_file_names'].split(',')
        self.good_dropped_file_types = self.config['production']['dropped_file_types'].split(',')

        # These are all of the things that we might parse out of a sandbox report.
        self.contacted_hosts = []
        self.created_services = []
        self.dns_requests = []
        self.dropped_files = []
        self.filename = ''
        self.http_requests = []
        self.indicators = []
        self.malware_family = ''
        self.md5 = ''
        self.memory_strings = []
        self.memory_urls = []
        self.mutexes = []
        self.path = ''
        self.process_tree_urls = []
        self.process_tree = ''
        self.process_trees = []
        self.process_trees_decoded = []
        self.processes = []
        self.resolved_apis = []
        self.sandbox_urls = []
        self.screenshot_path = ''
        self.screenshot_paths = []
        self.sha1 = ''
        self.sha256 = ''
        self.sha512 = ''
        self.ssdeep = ''
        self.started_services = []
        self.strings_urls = []

        # Load the report's JSON.
        if json_path:
            self.logger.debug("Loading sandbox JSON: " + json_path)
            self.path = json_path
            self.report = self.load_json(json_path)

    def __eq__(self, other):
        """ Return True if the MD5 hashes and the sandbox URLs are the same. """

        return (self.md5 == other.md5) and (self.sandbox_urls == other.sandbox_urls)

    @property
    def json(self):
        """ Make a JSON compatible view of the sandbox report. """

        json = {}
        json['contacted_hosts'] = self.contacted_hosts
        json['created_services'] = self.created_services
        json['dns_requests'] = self.dns_requests
        json['dropped_files'] = self.dropped_files
        json['filename'] = self.filename
        json['http_requests'] = self.http_requests
        json['malware_family'] = self.malware_family
        json['md5'] = self.md5
        json['memory_strings'] = self.memory_strings
        json['memory_urls'] = self.memory_urls
        json['mutexes'] = self.mutexes
        json['path'] = self.path
        json['process_tree_urls'] = self.process_tree_urls
        json['process_trees'] = self.process_trees
        json['process_trees_decoded'] = self.process_trees_decoded
        json['processes'] = self.processes
        json['resolved_apis'] = self.resolved_apis
        json['sandbox_urls'] = self.sandbox_urls
        json['screenshot_paths'] = self.screenshot_paths
        json['sha1'] = self.sha1
        json['sha256'] = self.sha256
        json['sha512'] = self.sha512
        json['ssdeep'] = self.ssdeep
        json['started_services'] = self.started_services
        json['strings_urls'] = self.strings_urls

        return json

    def make_contacted_host(self, ipv4='', port='', protocol='', location='', associated_domains=[]):
        """ JSON compatible view of a contacted host. """

        return {'ipv4': str(ipv4), 'port': str(port), 'protocol': str(protocol), 'location': str(location), 'associated_domains': associated_domains}

    def make_dropped_file(self, filename='', path='', size='', type='', md5='', sha1='', sha256='', sha512='', ssdeep=''):
        """ JSON compatible view of a dropped file. """

        return {'filename': str(filename), 'path': str(path), 'status': '', 'size': str(size), 'type': str(type), 'md5': str(md5), 'sha1': str(sha1), 'sha256': str(sha256), 'sha512': str(sha512), 'ssdeep': str(ssdeep)}

    def make_http_request(self, host='', port='', uri='', method='', user_agent=''):
        """ JSON compatible view of an HTTP request. """

        # Sometimes the Cuckoo reports have the port added to the host value. Strip that out.
        if ':' in host:
            host = host.split(':')[0]

        # Figure out the protocol to use for the URL.
        if str(port) == '443':
            protocol = 'https'
        else:
            protocol = 'http'

        # Figure out if the request used a non-standard port.
        if port and not str(port) == '80' and not str(port) == '443':
            full_url = '{}://{}:{}{}'.format(protocol, host, port, uri)
        else:
            full_url = '{}://{}{}'.format(protocol, host, uri)

        return {'host': str(host), 'port': str(port), 'uri': str(uri), 'method': str(method), 'user_agent': str(user_agent), 'url': str(full_url)}

    def make_dns_request(self, request='', type='', answer='', answer_type=''):
        """ JSON compatible view of a DNS request. """

        return {'request': str(request), 'type': str(type), 'answer': str(answer), 'answer_type': str(answer_type)}

    def make_process(self, command='', pid='', parent_pid=''):
        """ JSON compatible view of a process. """

        return {'command': str(command), 'decoded_command': '', 'pid': str(pid), 'parent_pid': str(parent_pid)}

    def make_process_tree(self, process_tree=None, text='', depth=0):
        """ Makes a pretty string representation of the process tree. """

        # Structure the list of processes if this is the first time calling the function.
        if not process_tree:
            # Operate on a copy of the list of processes since we need to modify it.
            process_tree = self.processes[:]

            # Get a list of the pids.
            pids = [proc['pid'] for proc in process_tree]

            # Get a list of the 'root' pids.
            root_pids = [proc['pid'] for proc in process_tree if not proc['parent_pid'] in pids]

            # Loop over all of the processes and add their children.
            for process in process_tree:
                process['children'] = [proc for proc in process_tree if proc['parent_pid'] == process['pid']]

            # At this point there are some duplicate processes in the list that appear
            # at the root process level that need to be removed.
            process_tree = [proc for proc in process_tree if proc['pid'] in root_pids]

        # Recursively build the process tree string.
        for process in process_tree:
            text += '{}{}\n'.format('    ' * depth, process['command'])

            if process['children']:
                text = self.make_process_tree(process['children'], text, depth+1)

        return text

    def load_json(self, json_path):
        """ Load the sandbox report JSON. """

        with open(json_path) as j:
            return json.load(j)

    def parse(self, json_dict, *json_keys, error=''):
        """ Parse an arbitrary key from the JSON. """

        for key in json_keys:
            try:
                json_dict = json_dict[key]
            except:
                return error
        return json_dict


def dedup_reports(report_list, whitelist):
    """ Merge a list of BaseSandboxParser subclass objects to make a single generic report. """

    logger = logging.getLogger()
    logger.debug('Deduping sandbox report list')

    # Create the new generic report.
    dedup_report = BaseSandboxParser()

    for report in report_list:
        dedup_report.sandbox_urls += report.sandbox_urls

        if report.filename and not report.filename == 'sample':
            dedup_report.filename = report.filename

        if report.md5:
            dedup_report.md5 = report.md5
            dedup_report.indicators.append(Indicator('Hash - MD5', dedup_report.md5, tags=['sandboxed_sample']))

        if report.sha1:
            dedup_report.sha1 = report.sha1
            dedup_report.indicators.append(Indicator('Hash - SHA1', dedup_report.sha1, tags=['sandboxed_sample']))

        if report.sha256:
            dedup_report.sha256 = report.sha256
            dedup_report.indicators.append(Indicator('Hash - SHA256', dedup_report.sha256, tags=['sandboxed_sample']))

        if report.sha512:
            dedup_report.sha512 = report.sha512
            # CRITS does not currently have a Hash - SHA512 indicator type.

        if report.ssdeep:
            dedup_report.ssdeep = report.ssdeep
            dedup_report.indicators.append(Indicator('Hash - SSDEEP', dedup_report.ssdeep, tags=['sandboxed_sample']))

        dedup_report.malware_family += report.malware_family

        # Dedup the contacted hosts.
        for host in report.contacted_hosts:
            if not host in dedup_report.contacted_hosts:
                dedup_report.contacted_hosts.append(host)
                tags = ['contacted_host']
                if host['protocol'] and host['port']:
                    tags.append('{} {}'.format(host['protocol'], host['port']))
                elif host['protocol']:
                    tags.append(host['protocol'])

                # For now we consider ALL contacted hosts to be benign, so no need to check the whitelist.
                dedup_report.indicators.append(Indicator('Address - ipv4-addr', host['ipv4'], status='Informational', tags=tags))

        # Dedup the dropped files.
        for file in report.dropped_files:

            # Dropped files are harder than the other items to properly whitelist, so we will
            # initially restrict them to certain file names or file types that we care about.
            if any(name in file['filename'] for name in dedup_report.good_dropped_file_names) or any(t in file['type'] for t in dedup_report.good_dropped_file_types):
                if not file in dedup_report.dropped_files:
                    dedup_report.dropped_files.append(file)

                    # If any part of the dropped file is whitelisted, make sure we mark all parts as whitelisted.
                    if whitelist.is_dropped_file_whitelisted(file):
                        status = 'Whitelisted'
                        file['status'] = 'Whitelisted'
                    else:
                        status = 'New'

                    dedup_report.indicators.append(Indicator('Windows - FileName', file['filename'], status=status, tags=['dropped_file']))
                    dedup_report.indicators.append(Indicator('Hash - MD5', file['md5'], status=status, tags=['dropped_file'], relationships=[file['sha1'], file['sha256']]))
                    dedup_report.indicators.append(Indicator('Hash - SHA1', file['sha1'], status=status, tags=['dropped_file'], relationships=[file['md5'], file['sha256']]))
                    dedup_report.indicators.append(Indicator('Hash - SHA256', file['sha256'], status=status, tags=['dropped_file'], relationships=[file['md5'], file['sha1']]))

        # Dedup the HTTP requests.
        for request in report.http_requests:
            if not request in dedup_report.http_requests:
                dedup_report.http_requests.append(request)
                dedup_report.indicators += make_url_indicators([request['url']], tags=['http_request', request['method']])

        # Dedup the DNS requests.
        for request in report.dns_requests:
            if not request in dedup_report.dns_requests:
                dedup_report.dns_requests.append(request)

                # If any part of the DNS request is whitelisted, make sure we mark all parts as whitelisted.
                if whitelist.is_dns_request_whitelisted(request):
                    status = 'Whitelisted'
                else:
                    status = 'New'

                # For now we consider ALL request IP addresses to be benign, so no need to check the whitelist.
                dedup_report.indicators.append(Indicator('URI - Domain Name', request['request'], tags=['dns_request']))
                try:
                    ipaddress.ip_address(request['answer'])
                    dedup_report.indicators.append(Indicator('Address - ipv4-addr', request['answer'], tags=['dns_response'], status='Informational', relationships=[request['request']]))
                except:
                    pass

        # Dedup the memory strings.
        dedup_report.memory_strings += report.memory_strings
        dedup_report.memory_strings = sorted(list(set(dedup_report.memory_strings)))

        # Dedup the memory URLs.
        dedup_report.memory_urls += report.memory_urls
        dedup_report.memory_urls = list(set(dedup_report.memory_urls))
        dedup_report.memory_urls = [u for u in dedup_report.memory_urls if is_valid(u)]
        dedup_report.indicators += make_url_indicators(dedup_report.memory_urls, tags=['url_in_memory'])

        # Dedup the strings URLs.
        dedup_report.strings_urls += report.strings_urls
        dedup_report.strings_urls = list(set(dedup_report.strings_urls))
        dedup_report.strings_urls = [u for u in dedup_report.strings_urls if is_valid(u)]
        dedup_report.indicators += make_url_indicators(dedup_report.strings_urls, tags=['url_in_strings'])

        # Dedup the mutexes.
        dedup_report.mutexes += report.mutexes
        dedup_report.mutexes = list(set(dedup_report.mutexes))

        # Dedup the resolved APIs.
        dedup_report.resolved_apis += report.resolved_apis
        dedup_report.resolved_apis = list(set(dedup_report.resolved_apis))

        # Dedup the created services.
        dedup_report.created_services += report.created_services
        dedup_report.created_services = list(set(dedup_report.created_services))

        # Dedup the started services.
        dedup_report.started_services += report.started_services
        dedup_report.started_services = list(set(dedup_report.started_services))

        # Add the process tree as-is.
        dedup_report.process_trees.append(report.process_tree)

        # Try to decode base64 chunks in the process tree.
        process_tree_decoded = report.process_tree
        for chunk in report.process_tree.split():
            try:
                decoded_chunk = base64.b64decode(chunk).decode('utf-8')
                if '\x00' in decoded_chunk:
                    decoded_chunk = base64.b64decode(chunk).decode('utf-16')
                process_tree_decoded = process_tree_decoded.replace(chunk, decoded_chunk)
            except:
                pass
        dedup_report.process_trees_decoded.append(process_tree_decoded)

        # Remove ` backtick and other basic Powershell obfuscation.
        new_trees = []
        for decoded_process_tree in dedup_report.process_trees_decoded:
            if 'powershell' in decoded_process_tree.lower():
                new_trees.append(decoded_process_tree.replace('`', ''))
        dedup_report.process_trees_decoded += new_trees

        # Remove Powershell string formatter obfuscation.
        new_trees = []
        for decoded_process_tree in dedup_report.process_trees_decoded:
            formatter_pattern = re.compile(r'(\([\'\"](({(\d+)})+)[\'\"]\s*\-f\s*(([\'\"][^\'\"]+[\'\"],*)+)\))', re.IGNORECASE)
            results = formatter_pattern.findall(decoded_process_tree)
            if results:
                for result in results:
                    """ ('("{0}{1}"-f\'JDxA\',\'QDc\')', '{0}{1}', '{1}', '1', "'JDxA','QDc'", "'QDc'") """
                    full_match = result[0]
                    order = result[1][1:-1] # 0}{1
                    items = result[4] # "'JDxA','QDc'"

                    order_list = order.split('}{')
                    order_ints = [int(x) for x in order_list]
                    
                    items_list = [i.replace('\'', '').replace('"', '') for i in items.split(',')]

                    if len(order_ints) == len(items_list):
                        deobfuscated_string = ''
                        for i in order_ints:
                            deobfuscated_string += items_list[i]
                        decoded_process_tree = decoded_process_tree.replace(full_match, deobfuscated_string)
                new_trees.append(decoded_process_tree)
        dedup_report.process_trees_decoded += new_trees

        # Try to decode string .split() obfuscation (used by Emotet and others)
        new_trees = []
        for decoded_process_tree in dedup_report.process_trees_decoded:
            if 'split' in decoded_process_tree.lower():
                try:
                    split_char_pattern = re.compile(r'\.[\'\"]*split[\'\"]*\([\'\"\s]*(.*?)[\'\"\s]*\)', re.IGNORECASE)
                    split_char = str(split_char_pattern.search(decoded_process_tree).group(1))
                    if split_char:
                        new_process_tree_decoded = ' '.join(decoded_process_tree.split(split_char))
                        new_process_tree_decoded = new_process_tree_decoded.replace("'+'", '')
                        new_process_tree_decoded = new_process_tree_decoded.replace('"+"', '')
                        new_process_tree_decoded = new_process_tree_decoded.replace('\'', ' ')
                        new_process_tree_decoded = new_process_tree_decoded.replace('\"', ' ')
                        new_process_tree_decoded = new_process_tree_decoded.replace('. ', ' ')
                        new_trees.append(new_process_tree_decoded)
                except:
                    logger.exception('Could not find process tree split() character.')
        dedup_report.process_trees_decoded += new_trees

        # Try to decode string .invoke() obfuscation (used by Emotet and others)
        new_trees = []
        for decoded_process_tree in dedup_report.process_trees_decoded:
            if 'invoke' in decoded_process_tree.lower():
                try:
                    split_char_pattern = re.compile(r'\.[\'\"]*invoke[\'\"]*\([\'\"\s]*(.*?)[\'\"\s]*\)', re.IGNORECASE)
                    split_char = str(split_char_pattern.search(decoded_process_tree).group(1))
                    if split_char:
                        new_process_tree_decoded = ' '.join(decoded_process_tree.split(split_char))
                        new_process_tree_decoded = new_process_tree_decoded.replace("'+'", '')
                        new_process_tree_decoded = new_process_tree_decoded.replace('"+"', '')
                        new_process_tree_decoded = new_process_tree_decoded.replace('\'', ' ')
                        new_process_tree_decoded = new_process_tree_decoded.replace('\"', ' ')
                        new_process_tree_decoded = new_process_tree_decoded.replace('. ', ' ')
                        new_trees.append(new_process_tree_decoded)
                except:
                    logger.exception('Could not find process tree invoke() character.')
        dedup_report.process_trees_decoded += new_trees

        # Dedup the process tree URLs. Start by just adding the URLs from each report.
        dedup_report.process_tree_urls += report.process_tree_urls
        # Find the URLs in each decoded process tree.
        for decoded_tree in dedup_report.process_trees_decoded:
            urls = find_urls(decoded_tree)
            # Remove any URL that has these URLs as substrings, since it's probably a bogus
            # URL from the original, non-decoded process tree.
            for u in report.process_tree_urls:
                if any(decoded_url in u for decoded_url in urls):
                    try:
                        dedup_report.process_tree_urls.remove(u)
                        logger.debug('Removing bad process tree URL: {}'.format(u))
                    except:
                        pass
            dedup_report.process_tree_urls += urls
        dedup_report.process_tree_urls = list(set(dedup_report.process_tree_urls))
        dedup_report.process_tree_urls = [u for u in dedup_report.process_tree_urls if is_valid(u)]
        dedup_report.indicators += make_url_indicators(dedup_report.process_tree_urls, tags=['url_in_process_tree'])

        # Add the screenshot URLs as-is.
        if report.screenshot_path:
            dedup_report.screenshot_paths.append(report.screenshot_path)

    return dedup_report
