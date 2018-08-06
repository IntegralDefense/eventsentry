import re
import base64
import html
from bs4 import BeautifulSoup
import contextlib
import sys
from urllib.parse import urlparse

_email_utf8_encoded_string = re.compile(r'.*(\=\?UTF\-8\?B\?(.*)\?=).*')
_email_address = re.compile(r'[a-zA-Z0-9._%+\-"]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9_-]{2,}')
_ip = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
_domain = re.compile(r'(((?=[a-zA-Z0-9-]{1,63}\.)[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,63})')
_url = re.compile(r'(((?:(?:https?|ftp)://)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-_]*)?\??(?:[\-\+=&;%@\.\w_:\?]*)#?(?:[\.\!\/\w:%\?&;=-]*))?(?<!=))')
_pdf_url = re.compile(r'Type\/Action\/S\/URI\/URI\((.*?)\)')
_bitly_url = re.compile(r'https?://bit.ly/[a-zA-Z0-9]{7}')
_md5 = re.compile(r'^[a-fA-F0-9]{32}$')
_sha1 = re.compile(r'^[a-fA-F0-9]{40}$')
_sha256 = re.compile(r'^[a-fA-F0-9]{64}$')
_sha512 = re.compile(r'^[a-fA-F0-9]{128}$')
_strings = re.compile(b'[\x20-\x7E]{4,}')
_widestrings = re.compile(b'(?:[\x20-\x7E]{1}\x00{1}){4,}')

class DummyFile(object):
    def write(self, x): pass
    
@contextlib.contextmanager
def nostderr():
    save_stderr = sys.stderr
    sys.stderr = DummyFile()
    yield
    sys.stderr = save_stderr

def decode_utf_b64_string(value):
    match = _email_utf8_encoded_string.match(value)
    
    if match:
        # Match the full encoded portion of the string. Ex: =?UTF-8?B?TsKqOTE4NzM4Lmh0bWw=?=
        encoded_string_full = match.group(1)
        
        # Match just the base64 portion of the string. Ex: TsKqOTE4NzM4Lmh0bWw=
        encoded_string_base64 = match.group(2)
        
        # Decode the base64.
        decoded_string_base64 = base64.b64decode(encoded_string_base64).decode("utf-8")
        
        # Set the return value equal to the original encoded value, but replace the
        # full encoded portion of the string with the decoded base64.
        return value.replace(encoded_string_full, decoded_string_base64)
    else:
        return value

def find_urls(value):
    # If we weren't given a string, try to convert it to ascii
    # since URLs should in theory be ascii anyway.
    if not isinstance(value, str):
        try:
            value = value.decode("ascii", errors="ignore")
        except AttributeError:
            value = ""
    else:
        value = bytes(value, "ascii", errors="ignore").decode("ascii", errors="ignore")

    unique_urls = []

    # Try to convert what we were given to soup and search for URLs.
    found_soup = False
    try:
        soup = BeautifulSoup(value, "html.parser")

        # Look for some valid HTML tags. We can't simply rely on whether
        # or not converting to soup was successful since BS4 is so lenient.
        valid_tags = ['</html>', '</body>', '</a>', '</script>', '</span>', '</div>', '</form>']
        if any(valid_tag in str(soup).lower() for valid_tag in valid_tags):
            found_soup = True
        else:
            found_soup = False
    except:
        found_soup = False

    if found_soup:
        # Find any href urls.
        tags = soup.find_all(href=True)
        for tag in tags:
            url = tag["href"]
            url = re.sub("\s+", "", url)
            unique_urls.append(url)

        # Find any src urls.
        tags = soup.find_all(src=True)
        for tag in tags:
            url = tag["src"]
            url = re.sub("\s+", "", url)
            unique_urls.append(url)

        # Find any action urls.
        tags = soup.find_all(action=True)
        for tag in tags:
            url = tag["action"]
            url = re.sub("\s+", "", url)
            unique_urls.append(url)

        # Use the old (regex) way to find URLs on the soup. This helps
        # catch any URLs that weren't href/src/action.
        urls = _url.findall(str(soup))
        unique_urls += [url if isinstance(url, str) else url[0] for url in urls]

    # If we couldn't convert what we were given to soup, fall back to the
    # messier way (regex) to find some urls.
    if not found_soup:
        # Try to de-quoted-printable the text.
        #unquoted = quopri.decodestring(value)

        #urls = _url.findall(unquoted)
        #temp = _pdf_url.findall(unquoted)
        urls = _url.findall(value)
        temp = _pdf_url.findall(value)
        pdf_urls = []
        for url in temp:
            if not url.lower().startswith("http://") and not url.lower().startswith("https://"):
                url = "http://" + url
            pdf_urls.append(url)
        urls += pdf_urls 
        unescaped_urls = [url if isinstance(url, str) else html.unescape(url[0]) for url in urls]

        # Try and remove any URLs that look like partial versions of other URLs.
        for url in unescaped_urls:  
            if not any(other_url.startswith(url) and other_url != url for other_url in unescaped_urls):
                unique_urls.append(url)

        # Check for embedded URLs inside other URLs.
        for url in unescaped_urls:
            for chunk in url.split("http://"):
                if chunk:
                    if not chunk.startswith("http://") and not chunk.startswith("https://") and not chunk.startswith("ftp://"):
                        if is_url("http://" + chunk):
                            unique_urls.append("http://" + chunk)

            for chunk in url.split("https://"):
                if chunk:
                    if not chunk.startswith("http://") and not chunk.startswith("https://") and not chunk.startswith("ftp://"):
                        if is_url("https://" + chunk):
                            unique_urls.append("https://" + chunk)

            for chunk in url.split("ftp://"):
                if chunk:
                    if not chunk.startswith("http://") and not chunk.startswith("https://") and not chunk.startswith("ftp://"):
                        if is_url("ftp://" + chunk):
                            unique_urls.append("ftp://" + chunk)

        # Remove any URLs that do not appear to be valid.
        for url in unique_urls[:]:
            parsed_url = urlparse(url)
            if not is_domain(parsed_url.netloc) and not is_ip(parsed_url.netloc):
                unique_urls.remove(url)

    # Try and specifically find any bit.ly URLs since these seem to be
    # the URL of choice when embedded inside Google URLs. I might add other
    # specific URL shorteners later.
    for url in unique_urls[:]:
        bitly_urls = _bitly_url.findall(url)
        for bitly_url in bitly_urls:
            unique_urls.append(bitly_url)

    # Remove any trailing "."'s from the URLs.
    unique_urls = [url[:-1] if url.endswith(".") else url for url in unique_urls]

    # Remove any trailing '/''s from the URLs.
    unique_urls = [url[:-1] if url.endswith("/") else url for url in unique_urls]
    
    return sorted(list(set(unique_urls)))
    
def find_strings(value):
    strings_matches = _strings.findall(value)
    strings = [str(s, 'utf-8') for s in strings_matches]
    
    widestrings_matches = _widestrings.findall(value)
    widestrings = [str(s, 'utf-8') for s in widestrings_matches]
    
    return strings + widestrings

def find_ip_addresses(value):
    return _ip.findall(value)

def find_domains(value):
    return [d[0] for d in _domain.findall(value)]

def find_email_addresses(value):
    return _email_address.findall(value)

def is_md5(value):
    try:
        if _md5.match(value):
            return True
        else:
            return False
    except TypeError:
        return False
    
def is_url(value):
    # If we weren't given a string, try to convert it to ascii
    # since URLs should in theory be ascii anyway.
    if not isinstance(value, str):
        try:
            value = value.decode("ascii", errors="ignore")
        except AttributeError:
            value = ""
    else:
        value = bytes(value, "ascii", errors="ignore").decode("ascii", errors="ignore")

    try:
        if _url.match(value):
            return True
        else:
            return False
    except TypeError:
        return False

def is_email_address(value):
    try:
        if _email_address.match(value):
            return True
        else:
            return False
    except TypeError:
        return False
    
def is_sha1(value):
    try:
        if _sha1.match(value):
            return True
        else:
            return False
    except TypeError:
        return False
    
def is_sha256(value):
    try:
        if _sha256.match(value):
            return True
        else:
            return False
    except TypeError:
        return False

def is_sha512(value):
    try:
        if _sha512.match(value):
            return True
        else:
            return False
    except TypeError:
        return False

def is_ip(value):
    try:
        if _ip.match(value):
            return True
        else:
            return False
    except TypeError:
        return False
    
def is_domain(value):
    try:
        if _domain.match(value):
            return True
        else:
            return False
    except TypeError:
        return False
