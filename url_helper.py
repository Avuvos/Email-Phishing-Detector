import re

# consider using urlparser instead of regex


# https://stackoverflow.com/questions/31350962/python-regex-for-detecting-all-the-urls-excluding-certain-domains
url_pattern = re.compile(r'(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)')


def is_url(text: str) -> bool:
    if url_pattern.match(text):
        # print(f"found a url: {text}")
        return True
    return False


# https://stackoverflow.com/questions/37437890/check-if-url-has-domain-name-and-not-an-ip
ip_pattern = re.compile(
    r'^https?://'
    r'([a-z0-9\.\-_%]+:([a-z0-9\.\-_%])+?@)?'
    r'((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.)'
    r'{3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])'
    r'(:[0-9]+)?'
    r'(\/[^\s]*)?$',
    re.IGNORECASE)


def check_if_contains_ip(text: str) -> bool:
    if ip_pattern.match(text):
        # print(f"found a url with IP: {text}")
        return True
    return False
