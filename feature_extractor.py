import re
import requests
import urllib
from bs4 import BeautifulSoup
import tldextract
from urllib.parse import urlparse, urlsplit
from datetime import datetime
import time
import dns.resolver
import whois
import os

def extract_features(url):
    hostname = urllib.parse.urlsplit(url).hostname or ''
    domain = tldextract.extract(url).domain
    domaincom = '.'.join(urlparse(url).netloc.split('.')[-2:])

    def url_length(u): return len(u)
    def having_ip_address(u):
        return 1 if re.search(r'(([0-9]{1,3}\.){3}[0-9]{1,3})', u) else 0
    def count_dots(h): return h.count('.')
    def count_hyphens(u): return u.count('-')
    def count_at(u): return u.count('@')
    def count_slash(u): return u.count('/')
    def count_double_slash(u):
        points = [x.start(0) for x in re.finditer('//', u)]
        return 1 if points and points[-1] > 6 else 0
    def count_http_token(u): return u.count('http')
    def ratio_digits(u): return len(re.sub("[^0-9]", "", u)) / len(u) if len(u) > 0 else 0
    def prefix_suffix(u):
        return 1 if re.findall(r"https?://[^\-]+-[^\-]+/", u) else 0
    def shortening_service(u):
        return 1 if re.search(r'(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co)', u) else 0

    # HTTP Requests
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        pagecontent = response.content
        nb_hyperlinks = len(soup.find_all('a'))
    except:
        pagecontent = ''
        nb_hyperlinks = 0

    def iframe(content):
        return 1 if not re.search(r"<iframe|frameBorder", str(content)) else 0
    def rightClick(content):
        return 1 if re.search(r"event.button ?== ?2", str(content)) else 0
    def domain_with_copyright(domain, content):
        try:
            match = re.search(u'(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN})', content)
            snip = content[match.start()-50:match.start()+50]
            return 0 if domain.lower() in snip.lower() else 1
        except:
            return 1

    soup = BeautifulSoup(pagecontent, 'html.parser', from_encoding='iso-8859-1')
    text_content = soup.get_text()

    def whois_registered_domain(domain):
        try:
            record = whois.whois(domain).domain_name
            if isinstance(record, list):
                return 0 if any(d.lower() in domain.lower() for d in record) else 1
            return 0 if record and record.lower() in domain.lower() else 1
        except:
            return 1

    def domain_registration_length(domain):
        try:
            res = whois.whois(domain)
            expiration_date = res.expiration_date
            today = datetime.utcnow()
            if expiration_date:
                if isinstance(expiration_date, list):
                    expiration_date = min(expiration_date)
                return abs((expiration_date - today).days)
            return 0
        except:
            return -1

    def domain_age_apivoid(host):
        try:
            key = os.getenv("APIVOID_KEY")
            url = f"https://endpoint.apivoid.com/domainage/v1/pay-as-you-go/?key={key}&host={host}"
            res = requests.get(url, timeout=5).json()
            return res['data']['domain_age_in_days']
        except:
            return -1

    def web_traffic(url):
        try:
            alexa = urllib.request.urlopen(f"http://data.alexa.com/data?cli=10&dat=s&url={url}")
            xml_soup = BeautifulSoup(alexa.read(), "xml")
            return int(xml_soup.find("REACH")['RANK'])
        except:
            return 0

    def dns_record(domaincom):
        try:
            return 0 if dns.resolver.resolve(domaincom, 'NS') else 1
        except:
            return 1

    def google_index(url):
        try:
            search_url = "https://www.google.com/search?q=site:" + url
            headers = {'User-Agent': 'Mozilla/5.0'}
            res = requests.get(search_url, headers=headers, timeout=5)
            return 1 if re.search("did not match any documents", res.text) else 0
        except:
            return 1

    def get_pagerank(domaincom):
        try:
            key = os.getenv("OPR_API_KEY")
            url = f'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D={domaincom}'
            res = requests.get(url, headers={'API-OPR': key}, timeout=5)
            return res.json()['response'][0]['page_rank_integer']
        except:
            return 0

    # Feature extraction
    features = [
        url_length(url),
        having_ip_address(url),
        count_dots(hostname),
        count_hyphens(url),
        count_at(url),
        count_slash(url),
        count_double_slash(url),
        count_http_token(url),
        ratio_digits(url),
        prefix_suffix(url),
        shortening_service(url),
        nb_hyperlinks,
        iframe(pagecontent),
        rightClick(pagecontent),
        domain_with_copyright(domain, text_content),
        whois_registered_domain(hostname),
        domain_registration_length(hostname),
        domain_age_apivoid(hostname),
        web_traffic(url),
        dns_record(domaincom),
        google_index(url),
        get_pagerank(domaincom),
    ]

    return features