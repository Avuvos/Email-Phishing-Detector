import sys
from utils import calculate_edit_distance, get_url_votes
from url_helper import is_url, check_if_contains_ip

URGENT_WORDS = {"urgent", "immediately", "action",
                "now", "fast", "quickly", "critical", "instantly", "instant",
                "act", "suspicious", "important",
                "verify", "password", "expired",
                "change", "leaked", "invoice"}

COMMON_VALID_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                        "icloud.com", "google.com", "linkedin.com", "youtube.com",
                        "facebook.com", "chess.com", "github.com", "paypal.com",
                        "amazon.com", "instagram.com", "twitter.com", "dropbox.com",
                        "microsoft.com", "ebay.com", "wikipedia.org", "netflix.com"]


# url is suspicious if it gets some malicious votes or has ip address in it
def check_for_suspicious_links(mail_word_list: list[str]) -> list[str]:
    urls_in_mail = [word for word in mail_word_list if is_url(word)]
    suspicious_links = []
    for url in urls_in_mail:
        malicious_votes = get_url_votes(url)
        if malicious_votes > 0:
            suspicious_links.append(f"url = {url} got {malicious_votes} malicious votes")
        contains_ip = check_if_contains_ip(url)
        if contains_ip:
            suspicious_links.append(f"url = {url} contains ip address")
    return suspicious_links


# address is suspicious if it is very similar to a valid domain but not quite the same
def check_for_spoofed_address(sender_domain: str) -> tuple[bool, str]:
    for domain in COMMON_VALID_DOMAINS:
        distance_from_domain = calculate_edit_distance(domain, sender_domain)
        if distance_from_domain == 0:  # matches exactly with a valid domain
            return False, ""
        if distance_from_domain <= 2:  # is 1 or 2 steps away from begin a valid domain
            return True, domain
    return False, ""


# returns a list of urgent words used in the mail
def check_for_urgent_language(mail_word_list: list[str]) -> list[str]:
    suspicious_words = []
    for word in mail_word_list:
        if word.lower() in URGENT_WORDS:
            suspicious_words.append(word)
    return suspicious_words


""" 
Assuming the input file is of the form:
    sender@domain
    email body
"""


def main():
    if len(sys.argv) < 2:
        print("No filename specified")
        exit(1)
    filename = sys.argv[1]
    try:
        with open(filename, 'r') as f:
            sender_address = f.readline().strip()
            sender_domain = sender_address.split("@")[1].lower()
            mail_content = f.read()
            mail_word_list = mail_content.split()
    except FileNotFoundError:
        print("File not found")
        exit(1)

    suspicious_links = check_for_suspicious_links(mail_word_list)
    suspicious_urgent_words = check_for_urgent_language(mail_word_list)
    is_spoofed_address, close_to_domain = check_for_spoofed_address(sender_domain)

    phishing_score = (int(is_spoofed_address) +
                      int(len(suspicious_urgent_words) > 0) +
                      int(len(suspicious_links) > 0))

    if phishing_score == 0:
        print("Email seems to be valid")
    else:
        print("Email might be dangerous due to the following reasons:")
        print()
        if is_spoofed_address:
            print(f"Notice that the sender domain is {sender_domain}\n"
                  f"which is very similar to {close_to_domain}\nbut not exactly!")
            print()

        if suspicious_links:
            print(f"Notice some suspicious urls were found:")
            for suspicious_link in suspicious_links:
                print(f"\t{suspicious_link}")
            print()

        if suspicious_urgent_words:
            print("Notice some suspicious urgent words were found:")
            for suspicious_word in suspicious_urgent_words:
                print(f"\t{suspicious_word}")


if __name__ == '__main__':
    main()