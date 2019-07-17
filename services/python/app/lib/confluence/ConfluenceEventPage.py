import datetime
import hashlib
import ipaddress
import json
import os
import time
from urlfinderlib import is_valid

from lib import indicator
from lib import RegexHelpers
from lib.config import config
from lib.confluence.BaseConfluencePage import *
from lib.constants import HOME_DIR


class ConfluenceEventPage(BaseConfluencePage):
    def __init__(self, page_title, sip, parent_title='Events'):
        # Run the super init to load the config and cache the page if it exists.
        super().__init__(page_title, parent_title=parent_title)

        # Save the SIP connection.
        self.sip = sip

        # If the page does not exist, spin up the template.
        if not self.page_exists():
            self.version = 1

            template_path = '/eventsentry/app/templates/confluence_event_template.txt'

            try:
                with open(template_path) as t:
                    template_text = t.read()
                self.soup = self.soupify(template_text)
                self.logger.debug('Wiki page "{}" does not exist. Using event template.'.format(page_title))
            except:
                self.logger.exception('Unable to open event template: ' + template_path)

            # Commit the page so that it actually exists. This allows attachments like screenshots
            # to work the first time instead of the second time the page/event is processed.
            self.commit_page()

    def is_event_ready_for_sip_processing(self, version_number):
        """ This event checks to make sure all the criteria are in place for the indicators to go into SIP. """

        # Only continue if the current page version is +1 from the old version. This implies
        # that the only change that happened was that someone checked the intel processing checkbox.
        if int(self.get_page_version()) - int(version_number) <= 1:
            if self.is_event_intel_processing_checked():
                overview_section = self.get_section('overview')
                try:
                    description = overview_section.find('p').text
                except:
                    description = ''

                if description:
                    return True

        return False

    def is_event_intel_processing_checked(self):
        """ This function reads whether or not the intel processing checkbox is checked. """

        section = self.get_section('expand_process_event')
        checkbox = str(section.find('ac:task-status'))

        if 'incomplete' in checkbox:
            return False
        else:
            return True

    def is_page_refresh_checked(self):
        """ This function reads whether or not the refresh page checkbox is checked. """

        section = self.get_section('refresh_wiki')
        checkbox = str(section.find('ac:task-status'))

        if 'incomplete' in checkbox:
            return False
        else:
            return True

    def read_manual_indicators(self):
        """ This function reads any indicators specified in the Manual Indicators section. """

        manual_indicators = []

        # Get a list of valid indicator types we've created in SIP.
        valid_indicator_types = [t['value'] for t in self.sip.get('/indicators/type')]

        # Get the visible text in the section.
        try:
            visible_text = self.get_section('manual_indicators').find('ac:plain-text-body').findAll(text=True)[0].splitlines()
        except:
            visible_text = []

        # Loop over each line in the visible text and see what indicators we can find.
        for line in visible_text:

            # Gross "fix" for the Â character that likes to appear in this section.
            # It appears to be the bytes 0xc382... No idea...
            # TODO: Figure out where this character keeps coming from.
            try:
                line = line.encode('ascii', errors='ignore').decode('ascii', errors='ignore')
            except:
                pass

            # Does this line have a comma in it? It might be a full indicator type/value/tags definition.
            full_indicator = False
            if ',' in line:
                split_line = line.split(',')

                # The split_line needs at least 2 elements: the indicator type and value. Tags are optional.
                if len(split_line) >= 2:
                    # Check if the first element is a valid SIP indicator type.
                    if split_line[0] in valid_indicator_types:
                        # Denote this line as full indicator so we don't reprocess it later.
                        full_indicator = True

                        indicator_type = split_line[0]
                        value = split_line[1].strip()

                        # Try to get any additional tags that were specified.
                        try:
                            tags = split_line[2:]
                        except:
                            tags = []

                        self.logger.debug('Found full manual indicator: {},{},{}'.format(indicator_type, value, tags))

                        # Make multiple indicators if the type is URI - URL.
                        if indicator_type == 'URI - URL':
                            manual_indicators += indicator.make_url_indicators(value, tags=tags)
                        # Otherwise just add the indicator as-is.
                        else:
                            manual_indicators.append(indicator.Indicator(indicator_type, value, tags=tags))

            # If this line wasn't a full indicator definition, try to extract some basic indicators from it.
            if not full_indicator:

                # Check if the line is a valid URL.
                if is_valid(line, fix=False):
                    manual_indicators += indicator.make_url_indicators(line)
                    self.logger.debug('Found regular URL in manual indicators: {}'.format(line))
                else:
                    # Find any domains in the line.
                    domains = RegexHelpers.find_domains(line)
                    for domain in domains:
                        manual_indicators.append(indicator.Indicator('URI - Domain Name', domain))
                        self.logger.debug('Found domain in manual indicators: {}'.format(domain))

                    # Find any IP addresses in the line.
                    ips = RegexHelpers.find_ip_addresses(line)
                    for ip in ips:
                        manual_indicators.append(indicator.Indicator('Address - ipv4-addr', ip))
                        self.logger.debug('Found IP in manual indicators: {}'.format(ip))

                    # Find any e-mail addresses in the line.
                    emails = RegexHelpers.find_email_addresses(line)
                    for email in emails:
                        manual_indicators.append(indicator.Indicator('Email - Address', email))
                        self.logger.debug('Found e-mail address in manual indicators: {}'.format(email))

        # Return the JSON form of the indicators.
        return [i.json for i in manual_indicators]

    def update_event_processed(self):
        """ This function is called after the indicators are added to SIP and closed in ACE. """

        # Reset the checkbox in the Process Event section.
        try:
            self.update_process_event()
        except:
            self.logger.exception('Unable to update the Process Event section.')

        # Reset the checkbox in the Refresh Wiki section.
        try:
            self.update_refresh_wiki('Indicators processed into SIP and closed in ACE: ')
        except:
            self.logger.exception('Unable to update the Refresh Wiki section.')

        # Save the page.
        self.commit_page()

    def refresh_event_page(self, event_json):
        """ This function is called when the page needs to be updated, whether the event
            has new critical files or the refresh wiki page box was checked. """

        # Time Table
        try:
            self.update_time_table(event_json)
        except:
            self.logger.exception('Unable to update the Time Table section.')

        # Refresh Wiki
        try:
            self.update_refresh_wiki('Event fully updated by the event sentry: ')
        except:
            self.logger.exception('Unable to update the Refresh Wiki section.')

        # Intel Processing
        try:
            self.update_intel_processing()
        except:
            self.logger.exception('Unable to update the Intel Processing section.')

        # Process Event
        try:
            self.update_process_event()
        except:
            self.logger.exception('Unable to update the Process Event section.')

        # Rebuild the Indicator Summary table.
        try:
            self.update_indicator_summary_table(event_json)
        except:
            self.logger.exception('Unable to update the Indicator Summary section.')

        # Reset the checkbox in the Process Event section.
        try:
            self.update_process_event()
        except:
            self.logger.exception('Unable to update the Process Event section.')

        # Reset the checkbox in the Refresh Wiki section.
        try:
            self.update_refresh_wiki('Wiki page refreshed by the event sentry: ')
        except:
            self.logger.exception('Unable to update the Refresh Wiki section.')

        # Artifacts
        try:
            self.update_artifacts(event_json['path'])
        except:
            self.logger.exception('Unable to update the Artifacts section.')

        # Event Detections
        try:
            self.update_event_detections(event_json)
        except:
            self.logger.exception('Unable to update the Event Detections section.')

        # Alerts
        try:
            self.update_alerts(event_json['ace_alerts'])
        except:
            self.logger.exception('Unable to update the Alerts section.')

        # SIP Analysis
        try:
            self.update_sip_analysis(event_json['indicators'])
        except:
            self.logger.exception('Unable to update the SIP Analysis section.')

        # Phish E-mail Information
        try:
            self.update_phish_info(event_json['emails'])
        except:
            self.logger.exception('Unable to update the Phish E-mail Information section.')

        # Phish Headers
        try:
            self.update_phish_headers(event_json['emails'])
        except:
            self.logger.exception('Unable to update the Phish Headers section.')

        # Phish Body
        try:
            self.update_phish_body(event_json['emails'])
        except:
            self.logger.exception('Unable to update the Phish Body section.')

        # ACE Screenshots
        try:
            self.update_ace_screenshots(event_json['ace_screenshots'])
        except:
            self.logger.exception('Unable to update the ACE Screenshots section.')

        # User Analysis
        try:
            self.update_user_analysis(event_json['ace_alerts'])
        except:
            self.logger.exception('Unable to update the User Analysis section.')

        # URL Analysis
        try:
            self.update_url_analysis(event_json['indicators'])
        except:
            self.logger.exception('Unable to update the URL Analysis section.')

        # Sandbox Analysis
        try:
            self.update_sandbox_analysis(event_json['sandbox'])
        except:
            self.logger.exception('Unable to update the Sandbox Analysis section.')

        # Update the page tags.
        try:
            self.update_tags(event_json)
        except:
            self.logger.exception('Unable to update the page tags.')

        # Save the page.
        self.commit_page()

    def read_indicator_summary_table(self):
        good_indicators = []
        whitelisted_indicators = []

        try:
            # Get all of the rows from the table.
            section = self.get_section('expand_indicator_summary')
            rows = section.find_all('tr')

            # Remove the first (header) row.
            rows = rows[1:]
        except:
            return [], []

        for row in rows:
            columns = row.find_all('td')

            # If, in rare cases, there are no tags to split, then it will throw an AttributeError.
            try:
                indicator = {'status': columns[0].string, 'type': columns[2].string,
                             'value': columns[3].string, 'tags': columns[4].string.split(',')}
            except AttributeError:
                indicator = {'status': columns[0].string, 'type': columns[2].string,
                             'value': columns[3].string, 'tags': columns[4].string}

            # If the whitelist checkbox is incomplete (unchecked), it is a good indicator.
            # Also, since we only display the whitelist checkboxes for New indicators, if there
            # is an exception when getting the checkbox string, we will assume it is a good indicator.
            try:
                whitelist = columns[1].find('ac:task-status').string
                if 'incomplete' in whitelist:
                    good_indicators.append(indicator)
                else:
                    whitelisted_indicators.append(indicator)
            except AttributeError:
                good_indicators.append(indicator)

        return good_indicators, whitelisted_indicators

    def update_tags(self, event_json):
        self.logger.debug('Updating tags on the wiki page.')

        # Remove any "apt:" event tags since those are not valid wiki tags.
        event_tags = [tag for tag in event_json['tags'] if not 'apt:' in tag]
        event_tags.append('events')

        # Add the event tags.
        wiki_labels = self.get_labels()
        for tag in set(event_tags):
            if not tag in wiki_labels:
                self.logger.debug('Adding label to wiki: {}'.format(tag))
                self.add_page_label(tag)
            else:
                self.logger.debug('Skipping label already on the wiki: {}'.format(tag))

        # Add the company names.
        company_names = set([a['company_name'] for a in event_json['ace_alerts']])
        for company_name in company_names:
            if not company_name in wiki_labels:
                self.logger.debug('Adding label to wiki: {}'.format(company_name))
                self.add_page_label(company_name)
            else:
                self.logger.debug('Skipping label already on the wiki: {}'.format(company_name))

        # Add the campaign if there is one.
        if event_json['campaign']:
            if not event_json['campaign']['wiki'] in wiki_labels:
                self.logger.debug('Adding label to wiki: {}'.format(event_json['campaign']['wiki']))
                self.add_page_label(event_json['campaign']['wiki'])
                self.add_page_label('campaign')
            else:
                self.logger.debug('Skipping label already on the wiki: {}'.format(event_json['campaign']['wiki']))
            

    def update_refresh_wiki(self, message):
        self.logger.debug('Updating Refresh Wiki section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Add the header tag.
        header = self.new_tag('h1', parent=div)
        header.string = 'Refresh Wiki'

        # Use the current time for the edit time.
        edit_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Add the edit time.
        edit_div = self.new_tag('div', parent=div)
        code = self.new_tag('code', parent=edit_div)
        code.string = message + edit_time

        # Create the warning message.
        check_div = self.new_tag('div', parent=div)
        check_div['style'] = 'font-weight: bold; color: red'

        # Create the checkbox.
        tasklist = self.new_tag('ac:task-list', parent=check_div)
        task = self.new_tag('ac:task', parent=tasklist)
        taskid = self.new_tag('ac:task-id', parent=task)
        taskid.string = '888888'
        taskstatus = self.new_tag('ac:task-status', parent=task)
        taskstatus.string = 'incomplete'
        taskbody = self.new_tag('ac:task-body', parent=task)
        taskbody.string = 'Check this box to have the event sentry refresh the wiki pages with your changes.'

        self.update_section(div, old_section_id='refresh_wiki')

    def update_intel_processing(self):
        self.logger.debug('Updating Intel Processing section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Add the header tag.
        header = self.new_tag('h1', parent=div)
        header.string = 'Intel Processing'

        self.update_section(div, old_section_id='intel_processing')

    def update_process_event(self):
        self.logger.debug('Updating Process Event section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Add the header tag.
        header = self.new_tag('h2', parent=div)
        header.string = 'Process Event'

        # Create the warning message.
        check_div = self.new_tag('div', parent=div)
        check_div['style'] = 'font-weight: bold; color: red'

        # Create the checkbox.
        tasklist = self.new_tag('ac:task-list', parent=check_div)
        task = self.new_tag('ac:task', parent=tasklist)
        taskid = self.new_tag('ac:task-id', parent=task)
        taskid.string = '999999'
        taskstatus = self.new_tag('ac:task-status', parent=task)
        taskstatus.string = 'incomplete'
        taskbody = self.new_tag('ac:task-body', parent=task)
        taskbody.string = '1) Add description in Overview. 2) Whitelist any bad indicators in the Indicator Summary. 3) Make sure wiki page has correct labels. 4) Set correct malware/campaign/etc in ACE.'

        self.update_section(div, old_section_id='expand_process_event')

    def update_indicator_summary_table(self, event_json):
        self.logger.debug('Updating Indicator Summary table.')

        # Used as a cache so we don't display duplicates in the table.
        queried_indicators = []

        # Holds the non-whitelisted indicators to display in the summary table.
        good_indicators = []

        # Holds the whitelisted indicators to display below the summary table.
        whitelisted_indicators = []

        # Populate the indicator lists.
        for i in event_json['indicators']:
            type_value_tags = '{}{}{}'.format(i['type'], i['value'], i['tags'])

            # Continue if we haven't already processed this type/value/tags pair indicator.
            if not type_value_tags in queried_indicators:

                # Add the indicator to the appropriate list.
                if not i['whitelisted']:
                    good_indicators.append(i)
                else:
                    whitelisted_indicators.append(i)

                # Add the indicator to the queried cache.
                queried_indicators.append(type_value_tags)

        # Start to figure out which event tags need to be added to the indicators.
        event_tags = event_json['tags']

        # Sort the good indicators by type then value.
        good_indicators = sorted(good_indicators, key=lambda x: (x['type'], x['value']))

        # Sort the whitelisted indicators by status, then type, then value.
        whitelisted_indicators = sorted(whitelisted_indicators, key=lambda x: (x['status'], x['type'], x['value']))

        # Create the parent div tag.
        div = self.new_tag('div')

        # Add the header tag.
        header = self.new_tag('h2', parent=div)
        header.string = 'Indicator Summary'

        # Create a new table tag.
        table = self.new_tag('table', parent=div)

        # Create a row in the table header row.
        tr = self.new_tag('tr', parent=table)

        # Create the table header elements.
        header_titles = ['Status', 'Whitelist', 'Type', 'Value', 'Tags']
        for title in header_titles:
            td = self.new_tag('td', parent=tr)
            td['style'] = 'font-weight: bold'
            td.string = title

        # Create rows for each indicator we were given.
        for i in range(len(good_indicators)):
            # Make the row for the indicator.
            tr = self.new_tag('tr', parent=table)

            # Set the status.
            td = self.new_tag('td', parent=tr)
            td.string = good_indicators[i]['status']

            # Set the whitelist status only if it is a New indicator.
            td = self.new_tag('td', parent=tr)
            if good_indicators[i]['status'] == 'New':
                tasklist = self.new_tag('ac:task-list', parent=td)
                task = self.new_tag('ac:task', parent=tasklist)
                taskid = self.new_tag('ac:task-id', parent=task)
                taskid.string = str(i)
                taskstatus = self.new_tag('ac:task-status', parent=task)
                taskstatus.string = 'incomplete'
                taskbody = self.new_tag('ac:task-body', parent=task)
                taskbody.string = ''

            # Set the type.
            td = self.new_tag('td', parent=tr)
            td.string = good_indicators[i]['type']

            # Set the value.
            td = self.new_tag('td', parent=tr)
            td.string = good_indicators[i]['value']

            # Set the tags.
            # Remove any tags we want to ignore from the event and indicator tags.
            tags = sorted(list(set(good_indicators[i]['tags'] + event_tags)))
            ignore_these_tags = config['wiki']['ignore_these_tags']
            for label in ignore_these_tags:
                try:
                    tags.remove(label)
                except:
                    pass
            td = self.new_tag('td', parent=tr)
            td.string = ','.join(tags)

        # Make a "header" for the PRE element.
        p = self.new_tag('p', parent=div)
        p['style'] = 'font-weight:bold;'
        p.string = 'Whitelisted Indicators'

        # Make the PRE element to hold the whitelisted indicators.
        pre = self.new_tag('pre', parent=div)
        pre['style'] = 'border:1px solid gray;padding:5px;'
        pre.string = ''
        for i in whitelisted_indicators:
            pre.string += '{} : {} : {}\n'.format(i['status'], i['type'], i['value'])

        self.update_section(div, old_section_id='expand_indicator_summary')

    def update_time_table(self, event_json):
        self.logger.debug('Updating Time Table section.')

        # Event Time
        if event_json['emails']:
            event_time = event_json['emails'][0]['received_time']
        elif event_json['ace_alerts']:
            event_time = event_json['ace_alerts'][0]['time']
        else:
            event_time = 'Unknown'

        # Alert Time
        if event_json['ace_alerts']:
            alert_time = event_json['ace_alerts'][0]['time']
        else:
            alert_time = 'Unknown'

        # Initial Detection
        if event_json['ace_alerts']:
            initial_detection = '{} ({})'.format(event_json['ace_alerts'][0]['tool'],
                                                 event_json['ace_alerts'][0]['type'])
        else:
            initial_detection = 'Unknown'

        # Delivery Vector
        if event_json['emails']:
            delivery_vector = 'PHISH'
        else:
            delivery_vector = ''

        # Compile the entire table dictionary.
        times_dict = {'Event Time': event_time,
                      'Alert Time': alert_time,
                      'Initial Detection': initial_detection,
                      'Delivery Vector': delivery_vector}

        # If the wiki page's version is 1 (just created), set the Created Time.
        if int(self.get_page_version()) == 1:
            try:
                offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
                offset = int(offset / 60 / 60 * -1)
                times_dict['Created Time'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC') + str(offset)
            except:
                times_dict['Created Time'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Get the existing time table and its data.
        existing_time_table = self.get_section('time_table')
        rows = existing_time_table.find_all('tr')
        data = [[td.find_all(text=True) for td in tr.find_all('td')] for tr in rows]

        # Create the parent div tag.
        div = self.new_tag('div')

        # Add the header tag.
        header = self.new_tag('h1', parent=div)
        header.string = 'Time Table'

        # Create a new table tag.
        table = self.new_tag('table', parent=div)

        # Loop over the existing table values to build the new table.
        for row in data:
            row_name = ''.join(row[0]).replace('  ', ' ')
            row_value = ''.join(row[1]).replace('  ', ' ')

            # Loop over the times_dict we were given to see if we need to update this row.
            for time_name in times_dict:
                time_value = times_dict[time_name]

                # If this time_name is in the current row_name, update it.
                if time_name in row_name:
                    row_value = time_value

            # Create the table row.
            tr = self.new_tag('tr', parent=table)

            # Create the first element in the row.
            td = self.new_tag('td', parent=tr)
            td['class'] = 'highlight-red'
            td['data-highlight-colour'] = 'red'
            td['style'] = 'font-weight: bold'
            td.string = row_name

            # Create the second element in the row.
            td = self.new_tag('td', parent=tr)
            td['class'] = 'highlight-red'
            td['data-highlight-colour'] = 'red'
            td.string = row_value

        self.update_section(div, old_section_id='time_table')

    def update_artifacts(self, path):
        self.logger.debug('Updating Artifacts section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Add the header tag.
        header = self.new_tag('h2', parent=div)
        header.string = 'Artifact Repository'

        # If we were given a server name/address, add it first.
        if config['wiki']['artifact_host']:
            artifact_host = config['wiki']['artifact_host']
            server_div = self.new_tag('div', parent=div)
            server_div['style'] = 'font-weight: bold'
            server_div.string = artifact_host

        # Add the path
        path_div = self.new_tag('div', parent=div)
        code = self.new_tag('code', parent=path_div)
        code.string = path

        self.update_section(div, old_section_id='artifact_repository')

    def update_event_detections(self, event_json):
        self.logger.debug('Updating Event Detections section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Make the section header.
        header = self.new_tag('h2', parent=div)
        header.string = 'Event Detections'

        # Make the pre tag to hold the detections.
        pre = self.new_tag('pre', parent=div)
        pre['style'] = 'border:1px solid gray;padding:5px;'
        pre.string = ''

        # Sort and display them.
        pre.string = '\n'.join(sorted(list(set(event_json['detections']))))

        self.update_section(div, old_section_id='event_detections')

        try:
            # Create the parent div tag.
            div = self.new_tag('div')

            # Make the section header.
            header = self.new_tag('h3', parent=div)
            header.string = 'Extra Event Detections'

            # Make the pre tag to hold the detections.
            pre = self.new_tag('pre', parent=div)
            pre['style'] = 'border:1px solid gray;padding:5px;'
            pre.string = ''

            # Sort and display them.
            pre.string = '\n'.join(sorted(list(set(event_json['detections_extra']))))

            self.update_section(div, old_section_id='expand_event_detections')
        except:
            pass

    def update_alerts(self, alert_json):
        self.logger.debug('Updating Alerts section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Add the header tag.
        header = self.new_tag('h2', parent=div)
        header.string = 'Alerts'

        # Create a new table tag.
        table = self.new_tag('table', parent=div)

        # Set up the table header row.
        thead = self.new_tag('thead', parent=table)
        tr = self.new_tag('tr', parent=thead)
        titles = ['URL', 'Time', 'Description', 'Tool', 'Type', 'Company']
        for title in titles:
            th = self.new_tag('th', parent=tr)
            th.string = title

        # Set up the table body rows.
        tbody = self.new_tag('tbody', parent=table)
        for alert in alert_json:
            tr = self.new_tag('tr', parent=tbody)

            td = self.new_tag('td', parent=tr)
            url = self.new_tag('a', parent=td)
            url['href'] = alert['url']
            url.string = 'Alert'

            td = self.new_tag('td', parent=tr)
            td.string = alert['time']

            td = self.new_tag('td', parent=tr)
            td.string = alert['description']

            td = self.new_tag('td', parent=tr)
            td.string = alert['tool']

            td = self.new_tag('td', parent=tr)
            td.string = alert['type']

            td = self.new_tag('td', parent=tr)
            td.string = alert['company_name'].title()

        self.update_section(div, old_section_id='alerts')

    def update_sip_analysis(self, indicator_json):
        self.logger.debug('Updating SIP Analysis section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Continue the section if we were given some indicators.
        if indicator_json:
            # The indicator JSON has duplicate indicators (Ex: if there are multiple phish emails).
            # We don't want to bother querying SIP multiple times for the same thing, so we will
            # keep track of the indicator values (not their types, since it's unlikely we'd have the
            # same value for two different types) that we query. Also, we only want to query SIP
            # for non-whitelisted and non-informational indicators.
            already_checked_indicators = []
            good_indicators = [i for i in indicator_json if not i['whitelisted'] and i['status'] == 'Analyzed']

            # Make the section header.
            header = self.new_tag('h2', parent=div)
            header.string = 'SIP Analysis'

            # Set up the pre tag to hold the results.
            pre = self.new_tag('pre', parent=div)
            pre.string = ''

            try:
                for indicator in good_indicators:
                    # Only continue if we haven't already queried for this indicator.
                    type_value = indicator['type'] + indicator['value']
                    if not type_value in already_checked_indicators:
                        # Cache this indicator type/value pair.
                        already_checked_indicators.append(type_value)

                        # Search SIP for any Analyzed indicators matching this one.
                        sip_indicators = self.sip.get('/indicators?status=Analyzed&type={}&exact_value={}'.format(indicator['type'], indicator['value']))

                        # Only continue if we got back at least 1 indicator.
                        if sip_indicators:
                            pre['style'] = 'border:1px solid gray;padding:5px;'

                            for sip_indicator in sip_indicators:
                                # Get the full details of each SIP indicator.
                                details = self.sip.get('/indicators/{}'.format(sip_indicator['id']))

                                # Get all of the indicator's unique references.
                                references = set()
                                source_names = set()
                                for reference in details['references']:
                                    source_names.add(reference['source'])
                                    references.add(reference['reference'])
                                references = sorted(list(references))
                                if len(references) > 10:
                                    references = references[-10:]
                                    references.append('<< Truncated list of older matching references >>')
                                source_names = sorted(list(source_names))

                                # We only want to display the indicator if either:
                                # 1) This wiki page is not a reference, OR
                                # 2) There are multiple references.
                                if len(references) > 1 or not self.get_page_url() in references:
                                    # Extract the values we care about.
                                    ind_value = details['value']
                                    ind_type = details['type']
                                    ind_tags = details['tags']
                                    ind_campaigns = set()
                                    for campaign in details['campaigns']:
                                        ind_campaigns.add(campaign['name'])
                                    ind_campaigns = sorted(list(ind_campaigns))

                                    # Add them to the pre's text.
                                    pre.string += ind_type + ': ' + ind_value + '\n'
                                    pre.string += 'Sources: ' + ', '.join(source_names) + '\n'
                                    pre.string += 'Campaigns: ' + ', '.join(ind_campaigns) + '\n'
                                    pre.string += 'Tags: ' + ', '.join(ind_tags) + '\n'

                                    for reference in references:
                                        if not self.get_page_url() == reference:
                                            pre.string += reference + '\n'

                                    pre.string += '\n'
                                else:
                                    self.logger.debug('Skipping indicator: {}'.format(details['value']))
            except:
                self.logger.exception('Unable to update the SIP Analysis section.')

        self.update_section(div, old_section_id='sip_analysis')

    def update_phish_info(self, email_json):
        self.logger.debug('Updating Phish Information section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Add the header tag.
        header = self.new_tag('h2', parent=div)
        header.string = 'Phish E-mail Information'

        if email_json:
            # Create a new table tag.
            table = self.new_tag('table', parent=div)

            # Set up the table header row.
            thead = self.new_tag('thead', parent=table)
            tr = self.new_tag('tr', parent=thead)
            titles = ['URL', 'Time', 'From', 'To', 'Subject', 'Attachments', 'CC', 'Reply-To', 'Message ID']
            for title in titles:
                th = self.new_tag('th', parent=tr)
                th.string = title

            """
            class="highlight-green confluenceTd" data-highlight-colour="green"
            """

            # Set up the table body rows.
            tbody = self.new_tag('tbody', parent=table)
            for email in email_json:
                tr = self.new_tag('tr', parent=tbody)

                td = self.new_tag('td', parent=tr)
                if email['ace_url']:
                    link = self.new_tag('a', parent=td)
                    link['href'] = email['ace_url']
                    link.string = 'Alert'
                if email['remediated']:
                    td['class'] = 'highlight-green confluenceTd'
                    td['data-highlight-colour'] = 'green'

                td = self.new_tag('td', parent=tr)
                td.string = email['received_time']
                if email['remediated']:
                    td['class'] = 'highlight-green confluenceTd'
                    td['data-highlight-colour'] = 'green'

                td = self.new_tag('td', parent=tr)
                td.string = email['from_address']
                if email['remediated']:
                    td['class'] = 'highlight-green confluenceTd'
                    td['data-highlight-colour'] = 'green'

                td = self.new_tag('td', parent=tr)
                if email['original_recipient']:
                    td.string = email['original_recipient']
                else:
                    td.string = ', '.join(email['to_addresses'])
                if email['remediated']:
                    td['class'] = 'highlight-green confluenceTd'
                    td['data-highlight-colour'] = 'green'

                td = self.new_tag('td', parent=tr)
                if email['subject_decoded']:
                    td.string = email['subject_decoded']
                else:
                    td.string = email['subject']
                if email['remediated']:
                    td['class'] = 'highlight-green confluenceTd'
                    td['data-highlight-colour'] = 'green'

                td = self.new_tag('td', parent=tr)
                td.string = ', '.join([a['name'] for a in email['attachments']])
                if email['remediated']:
                    td['class'] = 'highlight-green confluenceTd'
                    td['data-highlight-colour'] = 'green'

                """    
                td = self.new_tag('td', parent=tr)
                td.string = email.md5_string
                """

                td = self.new_tag('td', parent=tr)
                td.string = ', '.join(email['cc_addresses'])
                if email['remediated']:
                    td['class'] = 'highlight-green confluenceTd'
                    td['data-highlight-colour'] = 'green'

                td = self.new_tag('td', parent=tr)
                td.string = email['reply_to']
                if email['remediated']:
                    td['class'] = 'highlight-green confluenceTd'
                    td['data-highlight-colour'] = 'green'

                td = self.new_tag('td', parent=tr)
                td.string = email['message_id']
                if email['remediated']:
                    td['class'] = 'highlight-green confluenceTd'
                    td['data-highlight-colour'] = 'green'

        self.update_section(div, old_section_id='phish_email_information')

    def update_phish_headers(self, email_json):
        self.logger.debug('Updating Phish Headers section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Make the section header.
        header = self.new_tag('h2', parent=div)
        header.string = 'Phish Headers'

        # Continue the section if there are emails.
        if email_json:
            pre = self.new_tag('pre', parent=div)
            pre['style'] = 'border:1px solid gray;padding:5px;'

            # If there is an email with screenshots, we want to use those headers so that they
            # match up with the screenshots and body section.
            try:
                pre.string = next(email for email in email_json if email['screenshots'])['headers']
            except:
                pre.string = email_json[0]['headers']

        self.update_section(div, old_section_id='phish_headers')

    def update_phish_body(self, email_json):
        self.logger.debug('Updating Phish Body section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Make the section header.
        header = self.new_tag('h2', parent=div)
        header.string = 'Phish Body'

        # Continue the section if there are emails.
        if email_json:
            # Display the screenshots if there are any.
            screenshot_email = None
            try:
                screenshot_email = next(email for email in email_json if email['screenshots'])

                for screenshot in screenshot_email['screenshots']:
                    self.logger.debug('Updating Phish Body with screenshot: {}'.format(screenshot))
                    screenshot_name = os.path.basename(screenshot)

                    # Upload the screenshot as an attachment if it doesn't already exist.
                    if not self.attachment_exists(screenshot_name):
                        self.logger.debug('Attaching screenshot to wiki: {}'.format(screenshot))
                        self.attach_file(screenshot)

                    # If the screenshot attachment exists, add an img tag for it.
                    if self.attachment_exists(screenshot_name):
                        self.logger.debug('Adding screenshot to Phish Body section: {}'.format(screenshot_name))
                        screenshot_div = self.new_tag('div', parent=div)
                        img_p = self.new_tag('p', parent=screenshot_div)
                        img = self.new_tag('img', parent=img_p)
                        img['width'] = '1000'
                        src = '/download/attachments/{}/{}?effects=border-simple,blur-border,tape'.format(self.get_page_id(), screenshot_name)
                        img['src'] = src
            except:
                pass

            # Make the pre element for the email body.
            pre = self.new_tag('pre', parent=div)
            pre['style'] = 'border:1px solid gray;padding:5px;'

            # Figure out which email to display.
            if screenshot_email:
                email = screenshot_email
            else:
                email = email_json[0]

            # Prefer the plaintext body over the HTML body.
            if email['body']:
                pre.string = email['body']
            elif email['html']:
                pre.string = email['html']

        self.update_section(div, old_section_id='phish_body')

    def update_ace_screenshots(self, ace_screenshots):
        self.logger.debug('Updating ACE Screenshots section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Make the section header.
        header = self.new_tag('h2', parent=div)
        header.string = 'ACE Screenshots'

        # Display each non-HTML e-mail body screenshot.
        for screenshot_path in ace_screenshots:
            screenshot_name = os.path.basename(screenshot_path)

            # Upload the screenshot as an attachment if it doesn't already exist.
            if not self.attachment_exists(screenshot_name):
                self.attach_file(screenshot_path)

            screenshot_div = self.new_tag('div', parent=div)
            img_p = self.new_tag('p', parent=screenshot_div)
            img = self.new_tag('img', parent=img_p)
            img['width'] = '1000'
            #img['height'] = '562'
            src = '/download/attachments/' + str(self.get_page_id()) + '/' + screenshot_name + '?effects=border-simple,blur-border,tape'
            img['src'] = src

        self.update_section(div, old_section_id='ace_screenshots')

    def update_user_analysis(self, alert_json):
        self.logger.debug('Updating User Analysis section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Get the unique list of users from the alerts.
        unique_users = []
        for alert in alert_json:
            for user in alert['user_analysis']:
                if not user in unique_users:
                    unique_users.append(user)

        # Sort the users by their displayName.
        unique_users = sorted(unique_users, key=lambda x: x['displayName'])

        # Only continue if we actually have some users.
        if unique_users:
            # Add the header tag.
            header = self.new_tag('h2', parent=div)
            header.string = 'User Analysis'

            # Create a new table element.
            table = self.new_tag('table', parent=div)

            # Set up the table header row.
            titles = ['User ID', 'Name', 'E-mail', 'Title', 'Description', 'Company', 'OU']
            thead = self.new_tag('thead', parent=table)
            tr = self.new_tag('tr', parent=thead)
            for title in titles:
                th = self.new_tag('th', parent=tr)
                th.string = title

            # Set up the table body rows.
            tbody = self.new_tag('tbody', parent=table)
            for user in unique_users:
                tr = self.new_tag('tr', parent=tbody)

                td = self.new_tag('td', parent=tr)
                td.string = user['cn'].lower()

                td = self.new_tag('td', parent=tr)
                td.string = user['displayName']

                td = self.new_tag('td', parent=tr)
                if isinstance(user['mail'], list):
                    td.string = ', '.join(user['mail'])
                elif isinstance(user['mail'], str):
                    td.string = user['mail']

                td = self.new_tag('td', parent=tr)
                td.string = user['title']

                td = self.new_tag('td', parent=tr)
                td.string = user['description']

                td = self.new_tag('td', parent=tr)
                td.string = user['company']

                td = self.new_tag('td', parent=tr)
                td.string = user['distinguishedName']

        self.update_section(div, old_section_id='user_analysis')

    def update_url_analysis(self, indicator_json):
        self.logger.debug('Updating URL Analysis section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Make the section header.
        header = self.new_tag('h2', parent=div)
        header.string = 'URL Analysis'

        # Make the pre tag to hold the URLs.
        pre = self.new_tag('pre', parent=div)
        pre['style'] = 'border:1px solid gray;padding:5px;'
        pre.string = ''

        # Get all of the URL indicators.
        urls = []
        for i in indicator_json:
            if i['type'] == 'URI - URL':
                urls.append(i['value'])

        # Sort and display them.
        urls = sorted(list(set(urls)))
        pre.string = '\n'.join(urls)

        self.update_section(div, old_section_id='url_analysis')

    def update_sandbox_analysis(self, sandbox_json):
        self.logger.debug('Updating Sandbox Analysis section.')

        # Create the parent div tag.
        div = self.new_tag('div')

        # Add the header tag.
        header = self.new_tag('h2', parent=div)
        header.string = 'Sandbox Analysis'

        for report in sandbox_json:
            # Add a header for the sample's filename.
            header = self.new_tag('h3', parent=div)
            header.string = report['filename']

            """
            #
            # SANDBOX URLS
            #
            """
            self.logger.debug('Updating sandbox URLs for: {}'.format(report['md5']))

            # Make the new sub-section.
            sandbox_urls_section_id = 'sandbox_urls_{}'.format(report['md5'])
            sandbox_urls_section = self.make_section(sandbox_urls_section_id, parent=div)

            # Create a new parent div for the sub-section.
            sandbox_urls_div = self.new_tag('div')

            # Add a header tag for the URLs.
            header = self.new_tag('h4', parent=sandbox_urls_div)
            header.string = 'Sandbox URLs'

            # Add an unordered list for the reports.
            ul = self.new_tag('ul', parent=sandbox_urls_div)

            # Add list items for each report.
            for url in sorted(report['sandbox_urls']):
                li = self.new_tag('li', parent=ul)
                if 'cuckoo' in url:
                    display_name = 'Cuckoo'
                elif 'vxstream' in url:
                    display_name = 'VxStream'
                elif 'wildfire' in url:
                    display_name = 'Wildfire'
                else:
                    display_name = 'Unknown'
                link = self.new_tag('a', parent=li)
                link['href'] = url
                link.string = display_name

            if report['sha256']:
                li = self.new_tag('li', parent=ul)
                link = self.new_tag('a', parent=li)
                link['href'] = 'https://virustotal.com/en/file/{}/analysis/'.format(report['sha256'])
                link.string = 'VirusTotal'

            # Update the sub-section.
            self.update_section(sandbox_urls_div, old_section_soup=sandbox_urls_section)

            """
            #
            # SCREENSHOTS
            #
            """
            # Only continue if there are actually some screenshots.
            if report['screenshot_paths']:
                self.logger.debug('Updating screenshots for: {}'.format(report['md5']))

                # Make the new sub-section.
                screenshot_section_id = 'screenshot_' + report['md5']
                screenshot_section = self.make_section(screenshot_section_id, parent=div)

                # Create a new parent div for the sub-section.
                screenshots_div = self.new_tag('div')

                # Add a header tag for the screenshots.
                header = self.new_tag('h4', parent=screenshots_div)
                header.string = 'Screenshots'

                for screenshot_path in report['screenshot_paths']:
                    screenshot_name = os.path.basename(screenshot_path)

                    # Upload the screenshot as an attachment if it doesn't already exist.
                    if not self.attachment_exists(screenshot_name):
                        self.attach_file(screenshot_path)

                    img_p = self.new_tag('p', parent=screenshots_div)
                    img = self.new_tag('img', parent=img_p)
                    img['width'] = '1000'
                    img['height'] = '562'
                    src = '/download/attachments/{}/{}?effects=border-simple,blur-border,tape'.format(self.get_page_id(), screenshot_name)
                    img['src'] = src

                self.update_section(screenshots_div, old_section_soup=screenshot_section)

            """
            #
            # MUTEXES
            #
            """
            # Only continue if there are actually some mutexes.
            if report['mutexes']:
                self.logger.debug('Updating mutexes for ' + report['md5'])

                # Make the new sub-section.
                mutexes_section_id = 'mutexes_' + report['md5']
                mutex_section = self.make_section(mutexes_section_id, parent=div)

                # Create a new parent div for the sub-section.
                mutexes_div = self.new_tag('div')

                # Add a header tag for the mutexes.
                header = self.new_tag('h4', parent=mutexes_div)
                header.string = 'Mutexes'

                # Add a pre tag to hold them.
                pre = self.new_tag('pre', parent=mutexes_div)
                pre['style'] = 'border:1px solid gray;padding:5px;'
                pre.string = '\n'.join(sorted(list(set(report['mutexes']))))

                self.update_section(mutexes_div, old_section_soup=mutex_section)

            """
            #
            # DROPPED FILES
            #
            """
            # Only continue if there are actually any dropped files.
            if report['dropped_files']:
                self.logger.debug('Updating dropped files for ' + report['md5'])

                # Make the new sub-section.
                dropped_section_id = 'dropped_' + report['md5']
                dropped_section = self.make_section(dropped_section_id, parent=div)

                # Create a new parent div for the sub-section.
                dropped_div = self.new_tag('div')

                # Add a header tag for the dropped files.
                header = self.new_tag('h4', parent=dropped_div)
                header.string = 'Dropped Files'

                # Create a new table tag.
                table = self.new_tag('table', parent=dropped_div)

                # Set up the table header row.
                thead = self.new_tag('thead', parent=table)
                tr = self.new_tag('tr', parent=thead)
                titles = ['VirusTotal', 'Filename', 'Path', 'Size', 'Type', 'MD5', 'SHA256']
                for title in titles:
                    th = self.new_tag('th', parent=tr)
                    th.string = title

                # Set up the table body rows.
                tbody = self.new_tag('tbody', parent=table)
                for file in report['dropped_files']:
                    self.logger.debug('Adding row for dropped file: {} - {}'.format(file['filename'], file['md5']))
                    tr = self.new_tag('tr', parent=tbody)

                    td = self.new_tag('td', parent=tr)
                    if file['sha256']:
                        url = self.new_tag('a', parent=td)
                        vt_url = 'https://virustotal.com/en/file/{}/analysis/'.format(file['sha256'])
                        url['href'] = vt_url
                        url.string = 'VT'

                    td = self.new_tag('td', parent=tr)
                    td.string = file['filename']

                    td = self.new_tag('td', parent=tr)
                    td.string = file['path']

                    td = self.new_tag('td', parent=tr)
                    td.string = str(file['size'])

                    td = self.new_tag('td', parent=tr)
                    td.string = file['type']

                    td = self.new_tag('td', parent=tr)
                    td.string = file['md5']

                    td = self.new_tag('td', parent=tr)
                    td.string = file['sha256']

                # Update the sub-section.
                self.update_section(dropped_div, old_section_soup=dropped_section)

            """
            #
            # DNS REQUESTS
            #
            """
            # Only continue if there are actually any dropped files.
            if report['dns_requests']:
                self.logger.debug('Updating DNS requests for: {}'.format(report['md5']))

                # Make the new sub-section.
                dns_section_id = 'dns_' + report['md5']
                dns_section = self.make_section(dns_section_id, parent=div)

                # Create a new parent div for the sub-section.
                dns_div = self.new_tag('div')

                # Add a header tag for the DNS requests.
                header = self.new_tag('h4', parent=dns_div)
                header.string = 'DNS Requests'

                # Create a new table tag.
                table = self.new_tag('table', parent=dns_div)

                # Set up the table header row.
                thead = self.new_tag('thead', parent=table)
                tr = self.new_tag('tr', parent=thead)
                titles = ['VirusTotal', 'Request', 'Type', 'VirusTotal', 'Answer', 'Answer Type']
                for title in titles:
                    th = self.new_tag('th', parent=tr)
                    th.string = title

                # Set up the table body rows.
                tbody = self.new_tag('tbody', parent=table)
                for request in report['dns_requests']:
                    tr = self.new_tag('tr', parent=tbody)

                    td = self.new_tag('td', parent=tr)
                    url = self.new_tag('a', parent=td)
                    vt_url = 'https://virustotal.com/en/domain/{}/information/'.format(request['request'])
                    url['href'] = vt_url
                    url.string = 'VT'

                    td = self.new_tag('td', parent=tr)
                    td.string = request['request']

                    td = self.new_tag('td', parent=tr)
                    td.string = request['type']

                    td = self.new_tag('td', parent=tr)
                    if request['answer']:
                        try:
                            ipaddress.ip_address(request['answer'])
                            vt_url = 'https://virustotal.com/en/ip-address/{}/information/'.format(request['answer'])
                        except:
                            vt_url = 'https://virustotal.com/en/domain/{}/information/'.format(request['answer'])

                        url = self.new_tag('a', parent=td)
                        url['href'] = vt_url
                        url.string = 'VT'

                    td = self.new_tag('td', parent=tr)
                    td.string = request['answer']

                    td = self.new_tag('td', parent=tr)
                    td.string = request['answer_type']

                # Update the sub-section.
                self.update_section(dns_div, old_section_soup=dns_section)

            """
            #
            # HTTP REQUESTS
            #
            """
            # Only continue if there are actually any dropped files.
            if report['http_requests']:
                self.logger.debug('Updating HTTP requests for: {}'.format(report['md5']))

                # Make the new sub-section.
                http_section_id = 'http_' + report['md5']
                http_section = self.make_section(http_section_id, parent=div)

                # Create a new parent div for the sub-section.
                http_div = self.new_tag('div')

                # Add a header tag for the DNS requests.
                header = self.new_tag('h4', parent=http_div)
                header.string = 'HTTP Requests'

                # Create a new table tag.
                table = self.new_tag('table', parent=http_div)

                # Set up the table header row.
                thead = self.new_tag('thead', parent=table)
                tr = self.new_tag('tr', parent=thead)
                titles = ['VirusTotal', 'Method', 'Host', 'URI', 'Port', 'User-Agent']
                for title in titles:
                    th = self.new_tag('th', parent=tr)
                    th.string = title

                # Set up the table body rows.
                tbody = self.new_tag('tbody', parent=table)
                for request in report['http_requests']:
                    tr = self.new_tag('tr', parent=tbody)

                    td = self.new_tag('td', parent=tr)
                    url = self.new_tag('a', parent=td)
                    url_hash = hashlib.sha256(request['url'].encode()).hexdigest()
                    vt_url = 'https://virustotal.com/en/url/{}/analysis/'.format(url_hash)
                    url['href'] = vt_url
                    url.string = 'VT'

                    td = self.new_tag('td', parent=tr)
                    try:
                        td.string = request['method']
                    except:
                        self.logger.error(request)
                        self.logger.exception('Could not add HTTP method')

                    td = self.new_tag('td', parent=tr)
                    try:
                        td.string = request['host']
                    except:
                        self.logger.error(request)
                        self.logger.exception('Could not add HTTP host')

                    td = self.new_tag('td', parent=tr)
                    try:
                        td.string = request['uri']
                    except:
                        self.logger.error(request)
                        self.logger.exception('Could not add HTTP URI')

                    td = self.new_tag('td', parent=tr)
                    try:
                        td.string = request['port']
                    except:
                        self.logger.error(request)
                        self.logger.exception('Could not add HTTP port')

                    td = self.new_tag('td', parent=tr)
                    try:
                        td.string = request['user_agent']
                    except:
                        self.logger.error(request)
                        self.logger.exception('Could not add HTTP user-agent')

                # Update the sub-section.
                self.update_section(http_div, old_section_soup=http_section)

            """
            #
            # CONTACTED HOSTS
            #
            """
            # Only continue if there are actually any dropped files.
            if report['contacted_hosts']:
                self.logger.debug('Updating contacted hosts for: {}'.format(report['md5']))

                # Make the new sub-section.
                hosts_section_id = 'hosts_' + report['md5']
                hosts_section = self.make_section(hosts_section_id, parent=div)

                # Create a new parent div for the sub-section.
                hosts_div = self.new_tag('div')

                # Add a header tag for the DNS requests.
                header = self.new_tag('h4', parent=hosts_div)
                header.string = 'Contacted Hosts'

                # Create a new table tag.
                table = self.new_tag('table', parent=hosts_div)

                # Set up the table header row.
                thead = self.new_tag('thead', parent=table)
                tr = self.new_tag('tr', parent=thead)
                titles = ['VirusTotal', 'Address', 'Port', 'Protocol', 'Location', 'Associated Domains']
                for title in titles:
                    th = self.new_tag('th', parent=tr)
                    th.string = title

                # Set up the table body rows.
                tbody = self.new_tag('tbody', parent=table)
                for host in report['contacted_hosts']:
                    tr = self.new_tag('tr', parent=tbody)

                    td = self.new_tag('td', parent=tr)
                    url = self.new_tag('a', parent=td)
                    vt_url = 'https://virustotal.com/en/ip-address/{}/information/'.format(host['ipv4'])
                    url['href'] = vt_url
                    url.string = 'VT'

                    td = self.new_tag('td', parent=tr)
                    td.string = host['ipv4']

                    td = self.new_tag('td', parent=tr)
                    td.string = host['port']

                    td = self.new_tag('td', parent=tr)
                    td.string = host['protocol']

                    td = self.new_tag('td', parent=tr)
                    td.string = host['location']

                    td = self.new_tag('td', parent=tr)
                    td.string = ','.join(host['associated_domains'])

                # Update the sub-section.
                self.update_section(hosts_div, old_section_soup=hosts_section)

            """
            #
            # PROCESS TREES
            #
            """
            # Only continue if there are actually some process trees.
            if report['process_trees']:
                self.logger.debug('Updating process tree for: {}'.format(report['md5']))

                # Make the new sub-section.
                process_section_id = 'process_' + report['md5']
                process_section = self.make_section(process_section_id, parent=div)

                # Create a new parent div for the sub-section.
                process_div = self.new_tag('div')

                # Add a header tag for the mutexes.
                header = self.new_tag('h4', parent=process_div)
                header.string = 'Process Tree'

                # Add a pre tag to hold them.
                pre = self.new_tag('pre', parent=process_div)
                pre['style'] = 'border:1px solid gray;padding:5px;'
                pre.string = ''

                if report['process_trees_decoded']:
                    pre.string += '\n'.join(report['process_trees_decoded'])

                if report['process_trees']:
                    pre.string += '\n'.join(report['process_trees'])

                self.update_section(process_div, old_section_soup=process_section)

        self.update_section(div, old_section_id='sandbox_analysis')
