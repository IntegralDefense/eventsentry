import datetime
import logging
import subprocess
import tld

from lib.constants import PROXYCHAINS, PROXYCHAINS_CONFIG
from lib.modules.DetectionModule import *

class Module(DetectionModule):
    def __init__(self, name, event_json):

        super().__init__(name=name, event_json=event_json)

    def run(self):
        self.logger.debug('Running the {} detection module'.format(self.name))
    
        # There are some domains we don't care about since it's likely that it's just the attacker using their own address.
        ignore_domains = list(set(self.config.get('production', 'ignore_domains').split(',')))
    
        # This will hold the list of e-mail addresses to use when checking MX records.
        emails_to_check = []
    
        # Loop over each e-mail in the event and pull out potential e-mail addresses to check.
        for email in self.event_json['emails']:
            emails_to_check.append(email['from_address'])
            emails_to_check.append(email['return_path'])
            emails_to_check.append(email['x_auth_id'])
            emails_to_check.append(email['x_original_sender'])
            emails_to_check.append(email['x_sender_id'])
            emails_to_check.append(email['x_sender'])
    
        # Get the unique list of domains from the e-mail addresses we found.
        unique_domains = set()
        for address in emails_to_check:
            try:
                domain = address.split('@')[1]
                unique_domains.add(domain)
                tld_domain = tld.get_fld(domain, fix_protocol=True, fail_silently=True)
                if tld_domain:
                    unique_domains.add(tld_domain)
            except:
                pass
    
        # These are wiki page tags that, if present, we want to ignore the MITMB detection module.
        ignore_tags = list(set(self.config.get('production', 'ignore_tags').split(',')))
        if any(t in self.event_json['tags'] for t in ignore_tags):
            return
    
        # Filter out any of the domains we want to ignore.
        unique_domains = [domain for domain in unique_domains if not domain in ignore_domains]
    
        # Get the SPF record for each of the unique domains.
        spf_entries = set()
        for domain in unique_domains:
            try:
                try:
                    del os.environ['http_proxy']
                except:
                    pass
    
                try:
                    del os.environ['https_proxy']
                except:
                    pass
    
                command = '{} -f {} -q dig +noall +answer {} txt'.format(PROXYCHAINS, PROXYCHAINS_CONFIG, domain)
                output = subprocess.check_output(command, shell=True).decode('utf-8')
    
                # If there was output, we should have the SPF record.
                if output:
    
                    # Split the output lines.
                    for line in output.splitlines():
    
                        # Make sure the line looks like an SPF record.
                        if 'spf' in line:
    
                            # Split the line on spaces to get the "words".
                            words = line.split(' ')
    
                            # Loop over each word in the line to find include: domains or ip4: IP addresses.
                            for word in words:
                                if 'include:' in word:
                                    replaced = word.replace('include:', '')
                                    domain_tld = tld.get_fld(replaced, fix_protocol=True, fail_silently=True)
                                    if domain_tld:
                                        spf_entries.add((domain, domain_tld, output))
    
                                if 'mx:' in word:
                                    replaced = word.replace('mx:', '')
                                    domain_tld = tld.get_fld(replaced, fix_protocol=True, fail_silently=True)
                                    if domain_tld:
                                        spf_entries.add((domain, domain_tld, output))
    
                                if 'ip4:' in word:
                                    ip = word.replace('ip4:', '')
                                    if ip:
                                        spf_entries.add((domain, ip, output))
            except:
                self.logger.exception('Error when getting the SPF record for domain: {}'.format(domain))
    
        # Remove any blank entries.
        spf_entries = [thing for thing in spf_entries if thing]
    
        # Get the MX record for each of the unique domains.
        mx_entries = set()
        for domain in unique_domains:
            try:
                command = '{} -f {} -q dig +noall +answer {} MX'.format(PROXYCHAINS, PROXYCHAINS_CONFIG, domain)
                output = subprocess.check_output(command, shell=True).decode('utf-8')
    
                # If there was output, we should have the MX record.
                if output:
    
                    # Split the output lines.
                    for line in output.splitlines():
                        
                        # Split the line on spaces and take the last element as the answer domain.
                        # VISUALCOMFORTGROUP.COM: visualcomfortgroup.com.  1666    IN      MX      10 mx.usa.net.
                        answer_domain = line.split(' ')[-1]
                        if answer_domain.endswith('.'):
                            answer_domain = answer_domain[:-1]
    
                        # Get the TLD of the answer domain.
                        answer_tld = tld.get_fld(answer_domain, fix_protocol=True, fail_silently=True)
                        if answer_tld:
                            mx_entries.add((domain, answer_tld, output))
            except:
                self.logger.exception('Error when checking MX record for: {}'.format(domain))
    
        # Remove any blank entries.
        mx_entries = [thing for thing in mx_entries if thing]
    
        # Loop over each e-mail in the event and check for the SPF and MX entries.
        for email in self.event_json['emails']:
    
            # Get the index of the last (first in the list) received headers that has mimecast.com.
            # We need this since we will assume any received header prior to this index in the list
            # are "our" headers and should be removed when searching for the MX record answers.
            try:
                index = next(i for i, string in enumerate(email['received']) if 'mimecast.com' in string)
                received_headers = '\n'.join(email['received'][index+1:])
            except StopIteration:
                continue
    
            # Loop over each "word" in the received headers.
            for word in received_headers.split(' '):
    
                # Ignore the word if there is an @ in it, which implies it might be an e-mail address, which can cause FPs.
                if not '@' in word:
    
                    # Check if any of the SPF entries are in the word.
                    for spf in spf_entries:
                        if spf[1].lower() in word.lower():
                            self.extra.append(spf[2])
                            self.detections.append('Detected MITMB phish from domain "{}" by SPF record answer in headers: {}'.format(spf[0], spf[1]))
                            self.tags.append('mitmb')
    
                    # Check if any of the MX entries are in the word.
                    for mx in mx_entries:
                        if mx[1].lower() in word.lower():
                            self.extra.append(mx[2])
                            self.detections.append('Detected MITMB phish from domain "{}" by MX record answer in headers: {}'.format(mx[0], mx[1]))
                            self.tags.append('mitmb')
