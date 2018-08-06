import html
import logging
import urllib
from bs4 import BeautifulSoup

logger = logging.getLogger()


def run(event_json, good_indicators):
    logger.debug('Running the HTML text detection module.')

    tags = []
    detections = []
    extra = []

    # Keep a record of the HTML file's MD5 hash so we only loop over unique files.
    md5_cache = []

    # Loop over all of the HTML files in the event.
    for h in [f for f in event_json['files'] if f['category'] == 'html']:

        # Continue if we haven't already processed this MD5.
        if not h['md5'] in md5_cache:

            # Add the MD5 to the cache.
            md5_cache.append(h['md5'])

            # Read the contents of the HTML file.
            with open(h['path'], encoding='utf-8', errors='ignore') as f:
                file_text = f.read()
                
                # Store different forms of the HTML text.
                texts = []
                texts.append(file_text)
                try:
                    texts.append(str(BeautifulSoup(urllib.parse.unquote(file_text), 'html.parser')))
                except:
                    pass
                try:
                    texts.append(html.unescape(file_text))
                except:
                    pass

                # Run the detections for each form of the HTML text we have.
                for text in texts:

                    text = text.lower()

                    # 3 Apps creds harvester.
                    ss = ['3 Apps']
                    if all(s.lower() in text for s in ss):
                        additional = 'File Locked'
                        if additional.lower() in text:
                            detections.append('Detected the 3 Apps File Locked creds harvester by text "{}" and "{}": {}'.format(ss, additional, h['path']))
                            tags.append('3apps_filelocked')
                        else:
                            detections.append('Detected the 3 Apps creds harvester by text "{}": {}'.format(ss, h['path']))
                            tags.append('3apps')
                        tags.append('creds_harvesting')

                    # Account Verification creds harvester.
                    ss = ['Account Verification', '<form']
                    if all(s.lower() in text for s in ss):
                        detections.append('Detected the Account Verification creds harvester by the text "{}": {}'.format(ss, h['path']))
                        tags.append('creds_harvesting')
                        tags.append('verification_themed')

                    # Adobe creds harvester.
                    ss = ['Adobe PDF Online', 'Adobe Systems Inc', '%3D%2220%25%22%3EAdobe%20PDF%20Online', 'Adobe PDF Document', 'Secured Adobe', 'Adobe Security Systems', 'Adobe Online Viewer', 'D.O.C READER', 'PDF Reader', 'ADOBE DOCUMENT SECURITY SYSTEM', 'I Agree with Adobe.inc terms and conditions']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the Adobe creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('adobe_themed')

                    # chalbhai creds harvester.
                    s = 'chalbhai'
                    if s.lower() in text:
                        detections.append('Detected the chalbhai creds harvester by the text "{}": {}'.format(s, h['path']))
                        tags.append('creds_harvesting')
                        tags.append('chalbhai')

                    # Countdown creds harvester.
                    ss = ["document.write(unescape('%3c%74%69%74%6c%65%3e%45%6d%61%69%6c%20%53%65%74%74%69%6e%67%73%20%7c%20%56%65%72%69%66%69%63%61%74%69%6f%6e%3c%2f%74%69%74%6c%65%3e%0d%0a%0d%0a%3c%6c%69%6e",
                          "document.write(unescape('%3Ctitle%3E%u7535%u5B50%u90AE%u4EF6%u8BBE%u7F6E%7C%20%u9A8C%u8BC1"]
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the Countdown creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('verification_themed')
                            tags.append('countdown')

                    # Deactivation creds harvester.
                    ss = ['Account De-activation', 'Account Deactivation']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the Account Deactivation creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('deactivation_themed')

                    # DHL creds harvester.
                    ss = ['DHL WorldWide Delivery', 'DHL Now Partners with']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the DHL creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('dhl_themed')

                    # Document Management System creds harvester.
                    s = 'DOCUMENT MANAGEMENT SYSTEM'
                    if s.lower() in text:
                        detections.append('Detected the Document Management System creds harvester by the text "{}": {}'.format(s, h['path']))
                        tags.append('creds_harvesting')
                        tags.append('document_management_system')

                    # Docusign creds harvester.
                    s = '<title>Docusign</title>'
                    if s.lower() in text:
                        detections.append('Detected the Docusign creds harvester by the text "{}": {}'.format(s, h['path']))
                        tags.append('creds_harvesting')
                        tags.append('docusign_themed')

                    # Dropbox creds harvester.
                    ss = ['Dropbox Business', 'DropBox Buisness', 'Dropbox | Sign in']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the Dropbox creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('dropbox_themed')

                    # Excel creds harvester.
                    ss = ['Excel Online', 'Excel |']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the Excel creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('excel_themed')

                    # FileInvite creds harvester.
                    ss = ['<title>FileInvite</title>']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the FileInvite creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('fileinvite_themed')

                    # Google creds harvester.
                    ss = ['google-header-bar']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the Google creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('google_themed')

                    # i0281 creds harvester.
                    s = 'i0281'
                    if s.lower() in text:
                        detections.append('Detected the i0281 creds harvester by the text "{}": {}'.format(s, h['path']))
                        tags.append('creds_harvesting')
                        tags.append('i0281')

                    # LinkedIn creds harvester.
                    ss = ['<title>LinkedIn']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the LinkedIn creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('linkedin_themed')

                    # Mailbox creds harvester.
                    ss = ['<title>&#37038;&#20214;&#35774;&#32622;', '&#30830;&#35748;&#24744;&#30340;&#36134;&#25143;&#65292;&#36825;&#26679;&#20320;', '&#21487;&#20197;&#21319;&#32423;&#20320;&#30340;&#37038;&#31665;', '&#37038;&#20214;&#31649;&#29702;&#21592;']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the Mailbox creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('mailbox_themed')

                    # nahalo creds harvester.
                    s = 'nahalo'
                    if s.lower() in text:
                        detections.append('Detected the nahalo creds harvester by the text "{}": {}'.format(s, h['path']))
                        tags.append('creds_harvesting')
                        tags.append('nahalo')

                    # O365 creds harvester.
                    ss = ['secure.aadcdn.microsoftonline-p.com', 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJ8AAAAjCAYAAACKE9juAAAACXBIWXMAAC4jAAAuIwF4pT92AAAKT2lDQ1BQaG90b3Nob3', '©2018 Microsoft']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the O365 creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('o365_themed')

                    # OneDrive creds harvester.
                    ss = ['OneDrive online cloud', 'One Drive Cloud', '<title>OneDrive</title>']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the OneDrive creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('onedrive_themed')

                    # OX App Suite creds harvester.
                    ss = ['Open-Xchange', 'OX', 'App Suite']
                    if all(s.lower() in text for s in ss):
                        detections.append('Detected the OX App Suite creds harvester by the text "{}": {}'.format(ss, h['path']))
                        tags.append('creds_harvesting')
                        tags.append('ox_themed')

                    # Outlook creds harvester.
                    s = 'Outlook Web App'
                    if s.lower() in text:
                        detections.append('Detected the Outlook creds harvester by the text "{}": {}'.format(s, h['path']))
                        tags.append('creds_harvesting')
                        tags.append('outlook_themed')

                    # PayPal creds harvester.
                    ss = ['Paypal online']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the PayPal creds harvester by the text "{}": {}'.format(ss, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('paypal_themed')

                    # SharePoint creds harvester.
                    ss = ['Microsoft SharePoint', 'SharePoint</span>', 'Sharepoint.pdf', 'Sharepoint Cloud Document Sharing']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the SharePoint creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('sharepoint_themed')

                    # SmartSheet creds harvester.
                    ss = ['<title>Log In | Smartsheet</title>']
                    for s in ss:
                        if s.lower() in text:
                            detections.append('Detected the SmartSheet creds harvester by the text "{}": {}'.format(s, h['path']))
                            tags.append('creds_harvesting')
                            tags.append('smartsheet_themed')

                    # Webmail App creds harvester.
                    ss = ['Webmail Security Systems', 'Webmail App']
                    if all(s.lower() in text for s in ss):
                        detections.append('Detected the Webmail App creds harvester by the text "{}": {}'.format(ss, h['path']))
                        tags.append('creds_harvesting')
                        tags.append('webmail_app_themed')

                    # WeTransfer creds harvester.
                    ss = ['WeTransfer is the simplest way']
                    if all(s.lower() in text for s in ss):
                        detections.append('Detected the WeTransfer creds harvester by the text "{}": {}'.format(ss, h['path']))
                        tags.append('creds_harvesting')
                        tags.append('wetransfer_themed')

    return tags, detections, extra
