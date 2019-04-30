import os
import requests
import logging
import base64
from urlfinderlib import find_urls

from lib.parsers.BaseSandboxParser import *

class WildfireParser(BaseSandboxParser):
    def __init__(self, json_report_path):
        # Run the super init to inherit attributes and load the config.
        super().__init__(json_report_path)

        # Most Wildfire values depend on this.
        self.reports_json = self.parse(self.report, 'wildfire', 'task_info', 'report')

        # In case there was only a single report, make it a list anyway.
        if isinstance(self.reports_json, dict):
            self.reports_json = [self.reports_json]

        # Parse some basic info directly from the report.
        self.filename = 'sample'
        self.md5 = self.parse(self.report, 'wildfire', 'file_info', 'md5')
        self.sha1 = self.parse(self.report, 'wildfire', 'file_info', 'sha1')
        self.sha256 = self.parse(self.report, 'wildfire', 'file_info', 'sha256')

        # The rest of the info requires a bit more parsing.
        self.sandbox_urls = self.parse_sandbox_url()
        self.contacted_hosts = self.parse_contacted_hosts()
        self.dropped_files = self.parse_dropped_files()
        self.http_requests = self.parse_http_requests()
        self.dns_requests = self.parse_dns_requests()
        self.processes = self.parse_process_tree()
        self.process_tree = self.make_process_tree()
        self.process_tree_urls = self.parse_process_tree_urls()
        self.mutexes = self.parse_mutexes()

    def parse_sandbox_url(self):
        if self.sha256:
            return ['https://wildfire.paloaltonetworks.com/wildfire/reportlist?search=' + self.sha256]
        else:
            return []

    def parse_http_requests(self):
        self.logger.debug('Parsing HTTP requests')

        http_requests = []

        # Loop over each Wildfire report (usually should be 2).
        for report in self.reports_json:
            try:
                requests = report['network']['url']

                if isinstance(requests, dict):
                    requests = [requests]

                for request in requests:
                    try:
                        r = self.make_http_request(host=request['@host'], uri=request['@uri'], method=request['@method'], user_agent=request['@user_agent'])
                        http_requests.append(r)
                    except:
                        self.logger.exception('Error making HTTP request.')
            except:
                pass

        return http_requests

    def parse_dns_requests(self):
        self.logger.debug('Parsing DNS requests')

        dns_requests = []

        # Loop over each Wildfire report (usually should be 2).
        for report in self.reports_json:
            try:
                requests = report['network']['dns']

                if isinstance(requests, dict):
                    requests = [requests]

                for request in requests:
                    r = self.make_dns_request()

                    try: r['request'] = request['@query']
                    except: pass

                    try: r['type'] = request['@type']
                    except: pass

                    try: r['answer'] = request['@response']
                    except: pass

                    try: r['user_agent'] = request['@user_agent']
                    except: pass

                    dns_requests.append(r)
            except:
                pass

        return dns_requests

    def parse_dropped_files(self):
        self.logger.debug('Parsing dropped files')

        dropped_files = []

        # Loop over each Wildfire report (usually should be 2).
        for report in self.reports_json:
            try:
                processes = report['processes']['process']

                if isinstance(processes, dict):
                    processes = [processes]

                for process in processes:
                    try:
                        created_files = process['file']['Create']

                        if isinstance(created_files, dict):
                            created_files = [created_files]

                        for file in created_files:
                            d = self.make_dropped_file()

                            try: d['filename'] = file['@name'].split('\\')[-1]
                            except: pass

                            try: d['type'] = file['@type']
                            except: pass

                            try: d['path'] = file['@name']
                            except: pass

                            try: d['size'] = file['@size']
                            except: pass

                            try: d['md5'] = file['@md5']
                            except: pass

                            try: d['sha1'] = file['@sha1']
                            except: pass

                            try: d['sha256'] = file['@sha256']
                            except: pass

                            dropped_files.append(d)
                    except:
                        pass
            except:
                pass

        return dropped_files

    def parse_contacted_hosts(self):
        self.logger.debug('Parsing contacted hosts')

        contacted_hosts = []

        # Loop over each Wildfire report (usually should be 2).
        for report in self.reports_json:
            try:
                hosts = report['network']['TCP']

                if isinstance(hosts, dict):
                    hosts = [hosts]

                for host in hosts:
                    h = self.make_contacted_host()

                    try: h['ipv4'] = host['@ip']
                    except: pass

                    try: h['port'] = host['@port']
                    except: pass

                    try: h['protocol'] = 'TCP'
                    except: pass

                    try: h['location'] = host['@country']
                    except: pass

                    contacted_hosts.append(h)
            except:
                pass

            try:
                hosts = report['network']['UDP']

                if isinstance(hosts, dict):
                    hosts = [hosts]

                for host in hosts:
                    h = self.make_contacted_host()

                    try: h['ipv4'] = host['@ip']
                    except: pass

                    try: h['port'] = host['@port']
                    except: pass

                    try: h['protocol'] = 'UDP'
                    except: pass

                    try: h['location'] = host['@country']
                    except: pass

                    contacted_hosts.append(h)
            except:
                pass

        return contacted_hosts

    def parse_process_tree_urls(self):
        self.logger.debug('Looking for URLs in process tree')
        urls = []
        for process in self.processes:
            urls = find_urls(process['command'])
            urls += find_urls(process['decoded_command'])
        return urls

    def parse_process_tree(self):
        self.logger.debug('Parsing process tree')

        def walk_tree(process_json=None, processes=None, previous_pid=0):
            if not processes:
                processes = []

            if isinstance(process_json, dict):
                process_json = [process_json]

            if process_json:
                for process in process_json:
                    command = process['@text']
                    pid = process['@pid']
                    parent_pid = previous_pid
                    new_process = self.make_process(command, pid, parent_pid)
                    processes.append(new_process)
                    try:
                        processes = walk_tree(process['child']['process'], processes, pid)
                    except:
                        pass

            return processes

        process_tree_to_use = None
        process_tree_to_use_size = 0
        for report in self.reports_json:
            try:
                process_tree = report['process_tree']['process']
                process_tree_size = len(str(process_tree))
                if process_tree_size > process_tree_to_use_size:
                    process_tree_to_use = process_tree
                    process_tree_to_use_size = process_tree_size
            except:
                pass

        return walk_tree(process_json=process_tree_to_use)

    def parse_mutexes(self):
        self.logger.debug('Parsing mutexes')

        # We use a set instead of a list since there are multiple Wildfire reports.
        # This prevents any duplicate mutexes being returned.
        mutexes = set()

        # Loop over each Wildfire report (usually should be 2).
        for report in self.reports_json:
            try:
                processes = report['processes']['process']

                if isinstance(processes, dict):
                    processes = [processes]

                for process in processes:
                    try:
                        mutexes_created = process['mutex']['CreateMutex']

                        if isinstance(mutexes_created, dict):
                            mutexes_created = [mutexes_created]

                        for mutex in mutexes_created:
                            if mutex['@name'] != '<NULL>':
                                mutexes.add(mutex['@name'])
                    except:
                        pass
            except:
                pass

        return sorted(list(mutexes))
