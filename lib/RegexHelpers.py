import re

_email_utf8_encoded_string = re.compile(r'.*(\=\?UTF\-8\?B\?(.*)\?=).*')
_email_address = re.compile(r'[a-zA-Z0-9._%+\-"]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9_-]{2,}')
_ip = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
_domain = re.compile(r'(((?=[a-zA-Z0-9-]{1,63}\.)[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,63})')
_md5 = re.compile(r'^[a-fA-F0-9]{32}$')
_sha1 = re.compile(r'^[a-fA-F0-9]{40}$')
_sha256 = re.compile(r'^[a-fA-F0-9]{64}$')
_sha512 = re.compile(r'^[a-fA-F0-9]{128}$')
_strings = re.compile(b'[\x20-\x7E]{4,}')
_widestrings = re.compile(b'(?:[\x20-\x7E]{1}\x00{1}){4,}')

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
