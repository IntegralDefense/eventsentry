import os
import requests
import logging
import re
import base64
from urlfinderlib import find_urls
from urlfinderlib import is_valid

#from lib.url import find_urls
#from lib.url import is_valid
from lib.config import config
from lib.parsers.BaseSandboxParser import *

class VxstreamParser(BaseSandboxParser):
    def __init__(self, json_report_path):
        # Run the super init to inherit attributes and load the config.
        super().__init__(json_report_path)

        # Read some items from the config file.
        self.base_url = config['sandbox']['vxstream']['base_url']

        # Parse some basic info directly from the report.
        self.report_directory = os.path.dirname(json_report_path)
        self.sandbox_vm_name = self.parse(self.report, 'analysis', 'general', 'controller', 'client_name')
        self.filename = self.parse(self.report, 'analysis', 'general', 'sample')
        self.md5 = self.parse(self.report, 'analysis', 'general', 'digests', 'md5')
        self.sha1 = self.parse(self.report, 'analysis', 'general', 'digests', 'sha1')
        self.sha256 = self.parse(self.report, 'analysis', 'general', 'digests', 'sha256')
        self.sha512 = self.parse(self.report, 'analysis', 'general', 'digests', 'sha512')
        self.sample_id = str(self.parse(self.report, 'analysis', 'general', 'controller', 'environmentid'))

        # The rest of the info requires a bit more parsing.
        self.sandbox_urls = self.parse_sandbox_url()

        # Try the new method of picking the screenshot before the old slow method.
        self.screenshot_path = self.pick_best_screenshot()
        if not self.screenshot_path:
            self.screenshot_path = self.download_screenshot()

        self.contacted_hosts = self.parse_contacted_hosts()
        self.dropped_files = self.parse_dropped_files()
        self.http_requests = self.parse_http_requests()
        self.dns_requests = self.parse_dns_requests()

        # Fix the HTTP requests. VxStream seems to like to say the HTTP request
        # was made using the IP address, but if there is a matching DNS request
        # for this IP, swap in the domain name instead.
        for http_request in self.http_requests:
            for dns_request in self.dns_requests:
                if http_request['host'] == dns_request['answer']:
                    http_request['host'] = dns_request['request']

        self.processes = self.parse_process_tree()
        self.process_tree = self.make_process_tree()
        self.process_tree_urls = self.parse_process_tree_urls()
        self.memory_urls = self.parse_memory_urls()
        self.memory_strings = self.parse_memory_strings()
        self.mutexes = self.parse_mutexes()
        self.resolved_apis = self.parse_resolved_apis()

    def parse_memory_strings(self):
        memory_strings = []
        memory_string_files = [thing for thing in os.listdir(self.report_directory) if thing.endswith('.mstring')]
        for memory_string_file in memory_string_files:
            try:
                with open(os.path.join(self.report_directory, memory_string_file)) as f:
                    memory_strings += f.read().splitlines()
            except:
                self.logger.exception('Unable to parse VxStream memory strings.')
        return list(set(memory_strings))

    def parse_sandbox_url(self):
        return [self.base_url + '/sample/' + str(self.sha256) + '?environmentId=' + str(self.sample_id)]

    def pick_best_screenshot(self):
        potential_screenshots = [thing for thing in os.listdir(self.report_directory) if thing.startswith('screen_') and thing.endswith('.png')]
        if potential_screenshots:
            self.logger.debug('Picking the best screenshot using new method.')

            # Our VxStream VMs use the standard Windows background image, which
            # is quite large. In most cases, we want the medium filesize image.
            screenshots = {}
            for screenshot in potential_screenshots:
                path = os.path.join(self.report_directory, screenshot)
                size = int(os.path.getsize(path))
                screenshots[path] = size

            # Sort the screenshots by their size.
            screenshots = sorted(screenshots.items(), key=lambda x: x[1])

            # Find the middle index value.
            num_screenshots = len(screenshots)
            if num_screenshots % 2 == 0:
                best_screenshot_index = int(num_screenshots / 2)
            else:
                best_screenshot_index = int((num_screenshots / 2) - 0.5)

            # Grab the best screenshot.
            best_screenshot_path = screenshots[best_screenshot_index][0]

            # If we picked a best screenshot, return that as the path.
            if best_screenshot_path:
                # Rename the screenshot so it doesn't get overwritten on wiki pages
                # in the event one with the same name is uploaded to the page.
                new_name = 'screen_' + self.md5 + '.png'
                new_path = os.path.join(os.path.dirname(best_screenshot_path), new_name)
                try:
                    os.rename(best_screenshot_path, new_path)
                    self.logger.debug('Picked best screenshot "{}" and moved it to "{}"'.format(os.path.basename(best_screenshot_path), new_name))
                    return new_path
                except:
                    return None

    def download_screenshot(self):
        screenshot_path = os.path.join(self.report_directory, self.md5 + '_vxstream.png')

        if not os.path.exists(screenshot_path):
            url = self.parse_screenshot_url()

            if url:
                try:
                    self.logger.debug('Downloading screenshot ' + url)
                    request = requests.get(url, allow_redirects=True, verify=self.verify_requests)

                    if request.status_code == 200:
                        with open(screenshot_path, 'wb') as url_file:
                            url_file.write(request.content)

                        return screenshot_path
                except:
                    return None
        else:
            self.logger.debug('Screenshot already exists ' + screenshot_path)
            return screenshot_path

        return None

    def parse_screenshot_url(self):
        self.logger.debug('Picking best screenshot')

        screenshot_files = self.parse(self.report, 'analysis', 'final', 'imageprocessing', 'image')

        # If the screenshot_files JSON is a dictionary, that means only
        # 1 screenshot was taken. In this case, we don't want the screenshot.
        if isinstance(screenshot_files, dict):
            return ''

        screenshot_url = ''
        if screenshot_files:
            if len(screenshot_files) > 1:
                # Create a list of each screenshot URL.
                screenshot_urls = []
                for screenshot in screenshot_files:
                    screenshot_urls.append(self.base_url + '/sample/' + self.sha256 + '%23' + str(self.sample_id) + '/screenshots/' + screenshot['file'])

                # Get the size of each screenshot. VxStream uses a large image for its
                # desktop background, so in most cases, the smallest size screenshot will
                # be the most interesting (for example a Word document with lots of white).
                try:
                    smallest_size = 9999999
                    for url in screenshot_urls:
                        try:
                            size = int(requests.head(url, verify=self.verify_requests).headers['content-length'])
                            if size < smallest_size:
                                smallest_size = size
                                screenshot_url = url
                        except KeyError:
                            pass
                except:
                    return ''

        return screenshot_url

    def parse_http_requests(self):
        self.logger.debug('Parsing HTTP requests')

        http_requests = []
        http_requests_json = self.parse(self.report, 'analysis', 'runtime', 'network', 'httprequests', 'request')

        if http_requests_json:
            if isinstance(http_requests_json, dict):
                http_requests_json = [http_requests_json]

            for request in http_requests_json:
                try:
                    r = self.make_http_request(host=request['host'], port=request['dest_port'], uri=request['request_url'], method=request['request_method'])
                    try:
                        r['user_agent'] = request['useragent']
                    except:
                        pass
                    http_requests.append(r)
                except:
                    self.logger.exception('Error making HTTP request.')

        return http_requests

    def parse_dns_requests(self):
        self.logger.debug('Parsing DNS requests')

        dns_requests = []
        dns_requests_json = self.parse(self.report, 'analysis', 'runtime', 'network', 'domains', 'domain')

        if dns_requests_json:
            if isinstance(dns_requests_json, dict):
                dns_requests_json = [dns_requests_json]

            if isinstance(dns_requests_json, str):
                dns_requests_json = [dns_requests_json]

            for request in dns_requests_json:
                r = self.make_dns_request()

                try: r['request'] = request['db']
                except KeyError: pass
                except TypeError: r[''] = request

                try: r['answer'] = request['address']
                except KeyError: pass
                except TypeError: pass

                # Only add the request if the host was successfully parsed.
                dns_requests.append(r)

        return dns_requests

    def parse_dropped_files(self):
        self.logger.debug('Parsing dropped files')

        dropped_files = []
        dropped_files_json = self.parse(self.report, 'analysis', 'runtime', 'dropped', 'file')

        if dropped_files_json:
            if isinstance(dropped_files_json, dict):
                dropped_files_json = [dropped_files_json]

            for file in dropped_files_json:
                f = self.make_dropped_file()

                try: f['filename'] = file['filename']
                except: pass

                try: f['path'] = file['vmpath']
                except: pass

                try: f['size'] = file['filesize']
                except: pass

                try: f['type'] = file['filetype']
                except: pass

                try: f['md5'] = file['md5']
                except: pass

                try: f['sha1'] = file['sha1']
                except: pass

                try: f['sha256'] = file['sha256']
                except: pass

                try: f['sha512'] = file['sha512']
                except: pass

                dropped_files.append(f)

        return dropped_files

    def parse_contacted_hosts(self):
        self.logger.debug('Parsing contacted hosts')

        contacted_hosts = []
        contacted_hosts_json = self.parse(self.report, 'analysis', 'runtime', 'network', 'hosts', 'host')

        if contacted_hosts_json:
            if isinstance(contacted_hosts_json, dict):
                contacted_hosts_json = [contacted_hosts_json]

            for host in contacted_hosts_json:
                h = self.make_contacted_host()

                try: h['ipv4'] = host['address']
                except: pass

                try: h['port'] = host['port']
                except: pass

                try: h['protocol'] = host['protocol']
                except: pass

                try: h['location'] = host['country'] + ' (ASN: ' + str(host['asn']) + ' - ' + host['as_owner'] + ')'
                except: pass

                contacted_hosts.append(h)

        return contacted_hosts

    def parse_process_tree_urls(self):
        self.logger.debug('Looking for URLs in process tree')
        urls = []
        for process in self.processes:
            urls += find_urls(process['command'])
            urls += find_urls(process['decoded_command'])
        return urls

    def parse_process_tree(self):
        self.logger.debug('Parsing process tree')

        process_tree_json = self.parse(self.report, 'analysis', 'runtime', 'targets', 'target')

        processes = []

        if process_tree_json:
            if isinstance(process_tree_json, dict):
                process_tree_json = [process_tree_json]

            for process in process_tree_json:
                command = str(process['name']) + ' ' + str(process['commandline'])
                pid = process['pid']
                parent_pid = process['parentpid']
                new_process = self.make_process(command, pid, parent_pid)
                processes.append(new_process)

        return processes

    def parse_memory_urls(self):
        self.logger.debug('Parsing memory URLs')
        memory_urls = set()
        memory_urls_json = self.parse(self.report, 'analysis', 'hybridanalysis', 'ipdomainstreams', 'stream')

        if memory_urls_json:
            if isinstance(memory_urls_json, dict):
                memory_urls_json = [memory_urls_json]

            for url in memory_urls_json:
                if isinstance(url, str):
                    if is_valid(url):
                        memory_urls.add(url)
                if isinstance(url, dict):
                    if 'db' in url:
                        if is_valid(url['db']):
                            memory_urls.add(url['db'])

        return sorted(list(memory_urls))

    def parse_mutexes(self):
        self.logger.debug('Parsing mutexes')

        mutex_list = set()
        process_tree_json = self.parse(self.report, 'analysis', 'runtime', 'targets', 'target')

        if process_tree_json:
            if isinstance(process_tree_json, dict):
                process_tree_json = [process_tree_json]

            for process in process_tree_json:
                try:
                    mutexes = process['mutants']['mutant']

                    if isinstance(mutexes, dict):
                        mutexes = [mutexes]

                    for mutex in mutexes:
                        mutex_list.add(mutex['db'])
                except:
                    pass

        return sorted(list(mutex_list))

    def parse_resolved_apis(self):
        self.logger.debug('Parsing resolved APIs')

        resolved_apis = set()
        hybrid_targets_json = self.parse(self.report, 'analysis', 'hybridanalysis', 'targets', 'target')

        if hybrid_targets_json:
            if isinstance(hybrid_targets_json, dict):
                hybrid_targets_json = [hybrid_targets_json]

            for target in hybrid_targets_json:
                try: streams = target['streams']['stream']
                except TypeError: streams = []

                if isinstance(streams, dict):
                    streams = [streams]

                for stream in streams:
                    try:
                        api_calls = stream['header']['apicalls']['apicall']

                        if isinstance(api_calls, dict):
                            api_calls = [api_calls]

                        for api_call in api_calls:
                            resolved_apis.add(api_call['symbol']['db'])
                    except KeyError:
                        pass
                    except TypeError:
                        pass

        return sorted(list(resolved_apis))

    def parse_strings_urls(self):
        self.logger.debug('Looking for URLs in strings')
        return find_urls(self.parse_strings())

    def parse_strings(self):
        self.logger.debug('Parsing strings')
        strings_json = self.parse(self.report, 'analysis', 'final', 'strings', 'string')
        strings_list = []

        if strings_json:
            if isinstance(strings_json, dict):
                strings_json = [strings_json]

            for string in strings_json:
                try: strings_list.append(string['db'])
                except KeyError: pass

        return '\n'.join(strings_list)
