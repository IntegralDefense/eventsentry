import os
import requests
import logging
import zipfile
import tempfile
import shutil
import base64
import re
from urltools.urltools import find_urls

#from lib.url import find_urls
from lib.parsers.BaseSandboxParser import *


class CuckooParser(BaseSandboxParser):
    def __init__(self, json_report_path):
        # Run the super init to inherit attributes and load the config.
        super().__init__(json_report_path)

        # Read some items from the config file.
        self.base_url = self.config['production']['cuckoo_base_url']

        # Parse some basic info directly from the report.
        self.report_directory = os.path.dirname(json_report_path)
        self.sandbox_vm_name = self.parse(self.report, 'info', 'machine', 'name')
        self.filename = self.parse(self.report, 'target', 'file', 'name')
        self.md5 = self.parse(self.report, 'target', 'file', 'md5')
        self.sha1 = self.parse(self.report, 'target', 'file', 'sha1')
        self.sha256 = self.parse(self.report, 'target', 'file', 'sha256')
        self.sha512 = self.parse(self.report, 'target', 'file', 'sha512')
        self.ssdeep = self.parse(self.report, 'target', 'file', 'ssdeep')
        self.malware_family = self.parse(self.report, 'malfamily')
        self.sample_id = str(self.parse(self.report, 'info', 'id'))

        # The rest of the info requires a bit more parsing.
        self.sandbox_urls = self.parse_sandbox_url()
        self.screenshot_path = self.download_screenshot()
        self.contacted_hosts = self.parse_contacted_hosts()
        self.dropped_files = self.parse_dropped_files()
        self.http_requests = self.parse_http_requests()
        self.dns_requests = self.parse_dns_requests()
        self.processes = self.parse_process_tree()
        self.process_tree = self.make_process_tree()
        self.process_tree_urls = self.parse_process_tree_urls()
        self.mutexes = self.parse_mutexes()
        self.resolved_apis = self.parse_resolved_apis()
        self.created_services = self.parse_created_services()
        self.started_services = self.parse_started_services()
        #self.strings_urls = self.parse_strings_urls()

    def parse_sandbox_url(self):
        return [self.base_url + '/analysis/' + self.sample_id + '/']

    def download_screenshot(self):
        screenshot_zip_path = os.path.join(self.report_directory, self.md5 + '_cuckoo.zip')
        screenshot_path = os.path.join(self.report_directory, self.md5 + '_cuckoo.jpg')

        # If the screenshot .jpg hasn't already been cached...
        if not os.path.exists(screenshot_path):

            # If the screenshot .zip hasn't already been cached...
            if not os.path.exists(screenshot_zip_path):

                # This URL will download the .zip of all the screenshots.
                url = self.parse_screenshot_url()

                if url:
                    try:
                        request = requests.get(url, allow_redirects=True, verify=self.requests_verify)
                        self.logger.debug('Downloading screenshots .zip ' + url)

                        if request.status_code == 200:
                            with open(screenshot_zip_path, 'wb') as url_file:
                                url_file.write(request.content)

                    except requests.exceptions.ConnectionError:
                        return None

            # The .zip is cached, but the screenshot is not. Extract the .zip
            # to get at the screenshots. Extract them to a temp dir and pick
            # the 'best' screenshot from there to cache.
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(screenshot_zip_path, 'r') as zf:
                    zf.extractall(temp_dir)

                # Our VMs use a plain black Desktop background, so the logic
                # is that the largest filesize of the screenshots is going
                # to have the most 'stuff' on it, so we'll pick that one.
                best_screenshot = {'path': '', 'size': 0}
                for temp_screenshot in os.listdir(temp_dir):
                    temp_screenshot_path = os.path.join(temp_dir, temp_screenshot)
                    temp_screenshot_size = int(os.path.getsize(temp_screenshot_path))
                    if temp_screenshot_size > best_screenshot['size']:
                        best_screenshot['path'] = temp_screenshot_path
                        best_screenshot['size'] = int(temp_screenshot_size)

                # If we have a best screenshot, copy it out of the temp
                # directory into the screenshot cache.
                if best_screenshot['path']:
                    self.logger.debug('Copying screenshot from temp dir to cache: {}'.format(screenshot_path))
                    shutil.copy2(best_screenshot['path'], screenshot_path)
                    return screenshot_path
        else:
            return screenshot_path

    def parse_screenshot_url(self):
        return self.base_url + '/api/tasks/screenshots/' + str(self.sample_id)

    def parse_http_requests(self):
        self.logger.debug('Parsing HTTP requests')

        http_requests = []
        http_requests_json = self.parse(self.report, 'network', 'http')

        if http_requests_json:
            for request in http_requests_json:
                try:
                    r = self.make_http_request(host=request['host'], port=request['port'], uri=request['path'], method=request['method'], user_agent=request['user-agent'])
                    http_requests.append(r)
                except:
                    self.logger.exception('Error making HTTP request.')

        return http_requests

    def parse_dns_requests(self):
        self.logger.debug('Parsing DNS requests')

        dns_requests = []
        dns_requests_json = self.parse(self.report, 'network', 'dns')

        if dns_requests_json:
            for request in dns_requests_json:
                r = self.make_dns_request()
                try: r['request'] = request['request']
                except: pass

                try: r['type'] = request['type']
                except: pass

                # Technically, the Cuckoo JSON can have multiple answers listed,
                # but we are only going to grab the first one, as most of the time
                # there is only a single answer anyway.
                try: r['answer'] = request['answers'][0]['data']
                except: pass

                try: r['answer_type'] = request['answers'][0]['type']
                except: pass

                dns_requests.append(r)

        return dns_requests

    def parse_dropped_files(self):
        self.logger.debug('Parsing dropped files')
        dropped_files = []
        dropped_files_json = self.parse(self.report, 'dropped')

        if dropped_files_json:
            for file in dropped_files_json:
                f = self.make_dropped_file()

                try: f['filename'] = file['name']
                except: pass

                try: f['path'] = file['guest_paths'][0]
                except: pass

                try: f['size'] = file['size']
                except: pass

                try: f['type'] = file['type']
                except: pass

                try: f['md5'] = file['md5']
                except: pass

                try: f['sha1'] = file['sha1']
                except: pass

                try: f['sha256'] = file['sha256']
                except: pass

                try: f['sha512'] = file['sha512']
                except: pass

                try: f['ssdeep'] = file['ssdeep']
                except: pass

                dropped_files.append(f)

        return dropped_files

    def parse_contacted_hosts(self):
        self.logger.debug('Parsing contacted hosts')

        contacted_hosts = []
        contacted_hosts_json = self.parse(self.report, 'network', 'hosts')

        if contacted_hosts_json:
            for host in contacted_hosts_json:
                h = self.make_contacted_host()

                h['ipv4'] = host

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

        processes = []

        def walk_tree(process_json=None, processes=None):
            for process in process_json:
                command = process['command_line']
                pid = process['pid']
                parent_pid = process['ppid']
                new_process = self.make_process(command, pid, parent_pid)
                processes.append(new_process)
                processes = walk_tree(process['children'], processes)
            return processes

        return walk_tree(process_json=self.parse(self.report, 'behavior', 'processtree'), processes=processes)

    def parse_mutexes(self):
        self.logger.debug('Parsing mutexes')

        mutexes = set()
        mutexes_json = self.parse(self.report, 'behavior', 'summary', 'mutexes')

        if mutexes_json:
            for mutex in mutexes_json:
                mutexes.add(mutex)

        return sorted(list(mutexes))

    def parse_resolved_apis(self):
        self.logger.debug('Parsing resolved APIs')

        resolved_apis = set()
        resolved_apis_json = self.parse(self.report, 'behavior', 'summary', 'resolved_apis')

        if resolved_apis_json:
            for api_call in resolved_apis_json:
                resolved_apis.add(api_call)

        return sorted(list(resolved_apis))

    def parse_created_services(self):
        self.logger.debug('Parsing created services')

        created_services = set()
        created_services_json = self.parse(self.report, 'behavior', 'summary', 'created_services')

        if created_services_json:
            for service in created_services_json:
                created_services.add(service)

        return sorted(list(created_services))

    def parse_started_services(self):
        self.logger.debug('Parsing started services')

        started_services = set()
        started_services_json = self.parse(self.report, 'behavior', 'summary', 'started_services')

        if started_services_json:
            for service in started_services_json:
                started_services.add(service)

        return sorted(list(started_services))

    def parse_strings_urls(self):
        self.logger.debug('Looking for URLs in strings')
        return find_urls(self.parse_strings())

    def parse_strings(self):
        self.logger.debug('Parsing strings')
        strings_json = self.parse(self.report, 'strings')
        return '\n'.join(strings_json)
