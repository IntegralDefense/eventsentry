from bs4 import BeautifulSoup
import json
import logging
import os
import re
import requests

from lib.confluence.ConfluenceConnector import *


class BaseConfluencePage(ConfluenceConnector):
    def __init__(self, page_title, parent_title=None):
        # Run the super init to load the config.
        super().__init__()

        self.page_title = page_title
        self.parent_title = parent_title
        
        # Try to cache the page.
        self.cache_page()

    #####################
    ##                 ##
    ##  GET FUNCTIONS  ##
    ##                 ##
    #####################
    def page_exists(self):
        if self.cached_page:
            return True
        else:
            return False

    def cache_page(self):
        # Perform the API call to get the page.
        params = {'title': self.page_title, 'expand': 'body.storage,version', 'spaceKey': self.space_key}
        r = requests.get(self.api_url, auth=(self.username, self.password), params=params, verify=self.requests_verify)
        
        # If the call was successful, check if a result was actually returned.
        if self._validate_request(r, error_msg="Error with cache_page Confluence API query."):
            j = json.loads(r.text)
            # If there was a result, save the page and turn it into soup.
            if j["results"]:
                self.cached_page = j
                self.soup = self.soupify(self.get_page_text())
                self.logger.debug("Cached Confluence page: " + self.page_title)
            else:
                self.cached_page = None
                self.soup = BeautifulSoup("", "html.parser")
                self.logger.debug("Setting up blank cached page.")
                
    def get_page_url(self):
        if self.page_exists():
            return self.cached_page["_links"]["base"] + self.cached_page["results"][0]["_links"]["webui"]

    def get_page_text(self):
        if self.page_exists():
            return self.cached_page["results"][0]["body"]["storage"]["value"]

    def get_page_id(self):
        if self.page_exists():
            return str(self.cached_page["results"][0]["id"])
    
    def get_page_version(self):
        if self.page_exists():
            return self.cached_page["results"][0]["version"]["number"]
        
    def get_labels(self):
        if self.page_exists():
            page_id = self.get_page_id()
            r = requests.get(self.api_url + "/" + page_id + "/label", auth=(self.username, self.password), verify=self.requests_verify)
            
            if self._validate_request(r, error_msg="Error with get_labels Confluence API query."):
                j = json.loads(r.text)
                if j["results"]:
                    labels = [label["name"] for label in j["results"]]
                    return labels
                
        return []
        
    def attachment_exists(self, filename):
        if self.page_exists():
            page_id = self.get_page_id()
            params = {'filename': filename, 'expand': 'container,version', 'spaceKey': self.space_key}
            r = requests.get(self.api_url + "/" + page_id + "/child/attachment", auth=(self.username, self.password), params=params, verify=self.requests_verify)

            if self._validate_request(r, error_msg="Error with attachment_exists Confluence API query."):
                j = json.loads(r.text)
                if j["results"]:
                    return True
                
    def get_attachment_id(self, attachment_name):
        if self.page_exists():
            page_id = self.get_page_id()
            params = {'filename': attachment_name, 'expand': 'container,version', 'spaceKey': self.space_key}
            r = requests.get(self.api_url + "/" + page_id + "/child/attachment", auth=(self.username, self.password), params=params, verify=self.requests_verify)

            if self._validate_request(r, error_msg="Error with get_attachment_id Confluence API query."):
                j = json.loads(r.text)
                if j["results"]:
                    return (j["results"][0]["id"].replace("att", ""))
                
    def soupify(self, html):
        return BeautifulSoup(html, "html.parser")

    #######################
    ##                   ##
    ##  CACHE FUNCTIONS  ##
    ##                   ##
    #######################
    def new_tag(self, tag_name, parent=None):
        tag = self.soup.new_tag(tag_name)
        
        if parent:
            parent.append(tag)
        
        return tag
    
    def make_section(self, section_id, parent=None):
        if self.soup:
            new_section = self.new_tag("ac:structured-macro", parent=parent)
            new_section["ac:name"] = "section"
            new_section["ac:macro-id"] = section_id
            body = self.new_tag("ac:rich-text-body", parent=new_section)

            return new_section
                                            
    def section_exists(self, section_id):
        if self.soup:
            section = self.soup.find("ac:structured-macro", attrs={"ac:name": "section", "ac:macro-id": section_id})
            if section:
                return True
            else:
                return False
    
    def get_section(self, section_id):
        if self.soup:
            # Find the section. In theory, there should only ever be 1 result.
            section = self.soup.find("ac:structured-macro", attrs={"ac:name": "section", "ac:macro-id": section_id})

            # If we didn't find the section, maybe it's becasue we made it as an expand instead.
            if not section:
                section = self.soup.find("ac:structured-macro", attrs={"ac:name": "expand", "ac:macro-id": section_id})

            if section:
                return section
            else:
                self.logger.error("Did not find section '" + section_id + "' on page '" + self.page_title + "'.")

    def update_page(self, page_text):
        if self.page_exists():
            self.cached_page["results"][0]["body"]["storage"]["value"] = page_text

    def update_section(self, new_section, old_section_id=None, old_section_soup=None):
        # If we were given a string instead of soup, try to turn it into soup.
        if isinstance(new_section, str):
            new_section = self.soupify(new_section)

        if self.soup:
            # Check if we need to wrap the new section in the body tag.
            if len(new_section.contents) == 0:
                body = self.new_tag("ac:rich-text-body")
                body.append(new_section)
                new_section = body
            elif not new_section.contents[0].name == "ac:rich-text-body":
                body = self.new_tag("ac:rich-text-body")
                body.append(new_section)
                new_section = body

            if old_section_id:
                # Get the current version of the section.
                section = self.get_section(old_section_id)
            elif old_section_soup:
                if isinstance(old_section_soup, str):
                    old_section_soup = self.soupify(old_section_soup)
                section = old_section_soup
            
            # Update the section's body.
            section.find("ac:rich-text-body").replace_with(new_section)

            if old_section_id:
                # Now update the soup with the updated section.
                try:
                    self.soup.find(attrs={"ac:name": "section", "ac:macro-id": old_section_id}).replace_with(section)
                except AttributeError:
                    self.soup.find(attrs={"ac:name": "expand", "ac:macro-id": old_section_id}).replace_with(section)

                # Regenerate the soup.
                self.soup = self.soupify(str(self.soup))
            
            return section

    ##########################
    ##                      ##
    ##  POST/PUT FUNCTIONS  ##
    ##                      ##
    ##########################
    def create_page(self, page_text):
        # Strip out any bad XML characters.
        illegal_xml_re = re.compile(u'[\x00-\x08\x0b-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff\ufdd0-\ufddf\ufffe-\uffff]')
        page_text = illegal_xml_re.sub("", page_text)

        # Only create the page if it does not exist.
        if not self.page_exists():
            if self.parent_title:
                # If we were given a parent title, create an object from it.
                parent_page = BaseConfluencePage(self.parent_title)
                
                if parent_page.page_exists():
                    parent_id = parent_page.get_page_id()
                    data = {'type': 'page', 'title': self.page_title, 'space': {'key': self.space_key}, "ancestors": [{"id": parent_id}], 'body': {'storage': {'value': page_text, 'representation': 'storage'}}}
            else:
                data = {'type': 'page', 'title': self.page_title, 'space': {'key': self.space_key}, 'body': {'storage': {'value': page_text, 'representation': 'storage'}}}

            # Perform the API call to make the page.
            r = requests.post(self.api_url, auth=(self.username, self.password), data=json.dumps(data), headers=({'Content-Type':'application/json'}), verify=self.requests_verify)
            
            # If the call was successful, cache the page.
            try:
                if self._validate_request(r, error_msg="Unable to create page '" + self.page_title + "'."):
                    self.logger.debug("Created Confluence page: " + self.page_title)
                    self.cache_page()
            except ValueError:
                self.logger.exception(repr(page_text))

    def commit_page(self):
        if not self.page_exists() and self.soup:
            self.create_page(str(self.soup))

        # Use the self.soup as the source for the page text.
        page_id = self.get_page_id()
        page_current_version = self.get_page_version()
        cached_page_text = str(self.soup)

        # Strip out any bad XML characters.
        illegal_xml_re = re.compile(u'[\x00-\x08\x0b-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff\ufdd0-\ufddf\ufffe-\uffff]')
        cached_page_text = illegal_xml_re.sub("", cached_page_text)

        # Perform the API call to update the page.
        try:
            data = {'type': 'page', 'id': page_id, 'title': self.page_title, 'space': {'key': self.space_key}, 'body': {'storage': {'value': cached_page_text, 'representation': 'storage'}}, 'version': {'number': page_current_version+1}}
            r = requests.put(self.api_url + "/" + page_id, auth=(self.username, self.password), data=json.dumps(data), headers=({'Content-Type':'application/json'}), verify=self.requests_verify)
        except:
            self.logger.exception('Error committing changes to Confluence page: {}'.format(self.page_title))

        # If the call was successful, cache the page.
        if self._validate_request(r, error_msg="Error with commit_page Confluence API query."):
            self.logger.debug("Commiting changes to Confluence page: " + self.page_title)
            self.cache_page()
        else:
            self.logger.error("Error commiting changes to Confluence page: " + self.page_title)
            self.logger.error(cached_page_text)
                
    def attach_file(self, file_path):
        if self.page_exists():
            page_id = self.get_page_id()
            
            if os.path.exists(file_path):
                attachment = {"file": open(file_path, "rb")}
                r = requests.post(self.api_url + "/" + page_id + "/child/attachment", auth=(self.username, self.password), files=attachment, headers=({'X-Atlassian-Token':'nocheck'}), verify=self.requests_verify)
                if self._validate_request(r, error_msg="Unable to upload attachment '" + file_path + "'."):
                    self.logger.debug("Attached " + os.path.basename(file_path) + " to Confluence page " + self.page_title)
                    return True
                else:
                    return False

    def add_page_label(self, label):
        if self.page_exists():
            page_id = self.get_page_id()
            
            data = [{"prefix": "global", "name": label}]
            r = requests.post(self.api_url + "/" + page_id + "/label", auth=(self.username, self.password), data=json.dumps(data), headers=({'Content-Type':'application/json'}), verify=self.requests_verify)
            if self._validate_request(r, error_msg="Error with add_page_label Confluence API query."):
                self.logger.debug("Added label '" + label + "' to Confluence page " + self.page_title)
                return True
