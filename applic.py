from fastapi import FastAPI, HTTPException, Request, Form, Depends
from pydantic import BaseModel
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, String, Float, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import joblib
import pandas as pd
import uvicorn
import numpy as np
import requests
from urllib.parse import urlparse
import urllib.parse
import tldextract
import re
from bs4 import BeautifulSoup
import socket
import dns.resolver
import threading
from urllib.parse import urlencode
import concurrent.futures

# Database setup
DATABASE_URL = "sqlite:///./urls.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# URL model
class URL(Base):
    __tablename__ = "urls"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True)
    length_url = Column(Float)
    length_hostname = Column(Float)
    ip = Column(Integer)
    nb_dots = Column(Integer)
    nb_hyphens = Column(Integer)
    nb_at = Column(Integer)
    nb_qm = Column(Integer)
    nb_and = Column(Integer)
    nb_or = Column(Integer)
    nb_underscore = Column(Integer)
    nb_tilde = Column(Integer)
    nb_percent = Column(Integer)
    nb_slash = Column(Integer)
    nb_star = Column(Integer)
    nb_colon = Column(Integer)
    nb_comma = Column(Integer)
    nb_www = Column(Integer)
    nb_com = Column(Integer)
    nb_dslash = Column(Integer)
    http_in_path = Column(Integer)
    https_token = Column(Integer)
    ratio_digits_url = Column(Float)
    ratio_digits_host = Column(Float)
    tld_in_path = Column(Integer)
    tld_in_subdomain = Column(Integer)
    abnormal_subdomain = Column(Integer)
    nb_subdomains = Column(Integer)
    prefix_suffix = Column(Integer)
    shortening_service = Column(Integer)
    nb_external_redirection = Column(Integer)
    length_words_raw = Column(Integer)
    char_repeat = Column(Integer)
    shortest_words_raw = Column(Float)
    shortest_word_host = Column(Float)
    shortest_word_path = Column(Float)
    longest_words_raw = Column(Float)
    longest_word_host = Column(Float)
    longest_word_path = Column(Float)
    avg_words_raw = Column(Float)
    avg_word_host = Column(Float)
    avg_word_path = Column(Float)
    phish_hints = Column(Integer)
    domain_in_brand = Column(Integer)
    brand_in_subdomain = Column(Integer)
    brand_in_path = Column(Integer)
    suspicious_tld = Column(Integer)
    statistical_report = Column(Integer)
    nb_hyperlinks = Column(Integer)
    ratio_intHyperlinks = Column(Float)
    ratio_extHyperlinks = Column(Float)
    nb_extCSS = Column(Integer)
    ratio_intRedirection = Column(Float)
    ratio_extRedirection = Column(Float)
    ratio_extErrors = Column(Float)
    external_favicon = Column(Integer)
    links_in_tags = Column(Float)
    ratio_intMedia = Column(Float)
    ratio_extMedia = Column(Float)
    popup_window = Column(Integer)
    safe_anchor = Column(Float)
    empty_title = Column(Integer)
    domain_in_title = Column(Integer)
    domain_with_copyright = Column(Integer)
    dns_record = Column(Integer)
    google_index = Column(Integer)
    page_rank = Column(Float)


Base.metadata.create_all(bind=engine)

model_path = "new_rf_model.joblib"
features_path = "features (2).pkl"

try:
    model = joblib.load(model_path)
    features = pd.read_pickle(features_path)
    feature_names = features.columns.tolist()
except Exception as e:
    print(f"Error loading model or features: {e}")
    model = None
    features = None

app = FastAPI()
templates = Jinja2Templates(directory="templates")


class URLRequest(BaseModel):
    url: str


def having_ip_address(url):
    match = re.search(
        r'(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        r'([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
        r'((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        r'[0-9a-fA-F]{7}', url)
    if match:
        return 1
    else:
        return 0


def url_length(url):
    return len(url)


def shortening_service(full_url):
    match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      r'tr\.im|link\.zip\.net', full_url)
    if match:
        return 1
    else:
        return 0


def count_at(base_url):
    return base_url.count('@')


def count_comma(base_url):
    return base_url.count(',')


def count_and(base_url):
    return base_url.count('&')


def count_double_slash(full_url):
    list = [x.start(0) for x in re.finditer('//', full_url)]
    if list[len(list) - 1] > 6:
        return 1
    else:
        return 0


def count_slash(full_url):
    return full_url.count('/')


def count_percentage(base_url):
    return base_url.count('%')


def count_exclamation(base_url):
    return base_url.count('?')


def count_underscore(base_url):
    return base_url.count('_')


def count_hyphens(base_url):
    return base_url.count('-')


def count_dots(hostname):
    return hostname.count('.')


def count_colon(url):
    return url.count(':')


def count_star(url):
    return url.count('*')


def count_or(url):
    return url.count('|')


def count_tilde(url):
    return url.count('~')


def count_http_token(url_path):
    return url_path.count('http')


def https_token(scheme):
    if scheme == 'https':
        return 0
    return 1


def ratio_digits(hostname):
    return len(re.sub("[^0-9]", "", hostname)) / len(hostname)


def count_digits(line):
    return len(re.sub("[^0-9]", "", line))


def phish_hints(url_path):
    HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount',
             'dropbox', 'themes', 'plugins', 'signin', 'view']
    count = 0
    for hint in HINTS:
        count += url_path.lower().count(hint)
    return count


def tld_in_path(tld, path):
    if path.lower().count(tld) > 0:
        return 1
    return 0


def tld_in_subdomain(tld, subdomain):
    if subdomain.count(tld) > 0:
        return 1
    return 0


def tld_in_bad_position(tld, subdomain, path):
    if tld_in_path(tld, path) == 1 or tld_in_subdomain(tld, subdomain) == 1:
        return 1
    return 0


def abnormal_subdomain(url):
    if re.search(r'(http[s]?://(w[w]?|\d))([w]?(\d|-))', url):
        return 1
    return 0


def count_redirection(page):
    return len(page.history)


def count_external_redirection(page, domain):
    count = 0
    if len(page.history) == 0:
        return 0
    else:
        for i, response in enumerate(page.history, 1):
            if domain.lower() not in response.url.lower():
                count += 1
            return count


def char_repeat(words_raw):
    def __all_same(items):
        return all(x == items[0] for x in items)

    repeat = {'2': 0, '3': 0, '4': 0, '5': 0}
    part = [2, 3, 4, 5]
    for word in words_raw:
        for char_repeat_count in part:
            for i in range(len(word) - char_repeat_count + 1):
                sub_word = word[i:i + char_repeat_count]
                if __all_same(sub_word):
                    repeat[str(char_repeat_count)] = repeat[str(char_repeat_count)] + 1
    return sum(list(repeat.values()))


def domain_in_brand(domain):
    allbrand_txt = open("allbrands.txt", "r")

    def __txt_to_list(txt_object):
        list = []
        for line in txt_object:
            list.append(line.strip())
        txt_object.close()
        return list

    allbrand = __txt_to_list(allbrand_txt)
    if domain in allbrand:
        return 1
    else:
        return 0


def brand_in_path(domain, path):
    allbrand_txt = open("allbrands.txt", "r")

    def __txt_to_list(txt_object):
        list = []
        for line in txt_object:
            list.append(line.strip())
        txt_object.close()
        return list

    allbrand = __txt_to_list(allbrand_txt)
    for b in allbrand:
        if '.' + b + '.' in path and b not in domain:
            return 1
    return 0


def check_www(words_raw):
    count = 0
    for word in words_raw:
        if not word.find('www') == -1:
            count += 1
    return count


def check_com(words_raw):
    count = 0
    for word in words_raw:
        if not word.find('com') == -1:
            count += 1
    return count


def length_word_raw(words_raw):
    return len(words_raw)


def average_word_length(words_raw):
    if len(words_raw) == 0:
        return 0
    return sum(len(word) for word in words_raw) / len(words_raw)


def longest_word_length(words_raw):
    if len(words_raw) == 0:
        return 0
    return max(len(word) for word in words_raw)


def shortest_word_length(words_raw):
    if len(words_raw) == 0:
        return 0
    return min(len(word) for word in words_raw)


def prefix_suffix(url):
    if re.findall(r"https?://[^\-]+-[^\-]+/", url):
        return 1
    else:
        return 0


def count_subdomain(url):
    if len(re.findall(r"\.", url)) == 1:
        return 1
    elif len(re.findall(r"\.", url)) == 2:
        return 2
    else:
        return 3


def statistical_report(url, domain):
    url_match = re.search(
        r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    try:
        ip_address = socket.gethostbyname(domain)
        ip_match = re.search(
            r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
            r'107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
            r'118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
            r'216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
            r'34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
            r'216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
            ip_address)
        if url_match or ip_match:
            return 1
        else:
            return 0
    except:
        return 2


suspicious_tlds = ['fit', 'tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu', 'online', 'click',
                   'country', 'stream', 'download', 'xin', 'racing', 'jetzt',
                   'ren', 'mom', 'party', 'review', 'trade', 'accountants',
                   'science', 'work', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win',
                   'accountant', 'realtor', 'top', 'christmas', 'gdn',
                   'link',
                   'asia', 'club', 'la', 'ae', 'exposed', 'pe', 'go.id', 'rs', 'k12.pa.us', 'or.kr',
                   'ce.ke', 'audio', 'gob.pe', 'gov.az', 'website', 'bj', 'mx', 'media', 'sa.gov.au']


def suspicious_tld(tld):
    if tld in suspicious_tlds:
        return 1
    return 0


def nb_hyperlinks(dom):
    soup = BeautifulSoup(dom, 'html.parser')
    return len(soup.find_all(href=True)) + len(soup.find_all(src=True))


def h_total(dom):
    return nb_hyperlinks(dom)


def h_internal(Href, Link, Media, Form, CSS, Favicon):
    return len(Href['internals']) + len(Link['internals']) + len(Media['internals']) + len(Form['internals']) + len(
        CSS['internals']) + len(Favicon['internals'])


def internal_hyperlinks(dom, Href, Link, Media, Form, CSS, Favicon):
    total = h_total(dom)
    if total == 0:
        return 0
    else:
        return h_internal(Href, Link, Media, Form, CSS, Favicon) / total


def h_external(Href, Link, Media, Form, CSS, Favicon):
    return len(Href['externals']) + len(Link['externals']) + len(Media['externals']) + len(Form['externals']) + len(
        CSS['externals']) + len(Favicon['externals'])


def external_hyperlinks(dom, Href, Link, Media, Form, CSS, Favicon):
    total = h_total(dom)
    if total == 0:
        return 0
    else:
        return h_external(Href, Link, Media, Form, CSS, Favicon) / total


def external_css(CSS):
    return len(CSS['externals'])


def h_i_redirect(Href, Link, Media, Form, CSS, Favicon):
    count = 0
    for link in Href['internals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count += 1
        except:
            continue
    for link in Link['internals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count += 1
        except:
            continue
    for link in Media['internals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count += 1
        except:
            continue
    for link in Form['internals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count += 1
        except:
            continue
    for link in CSS['internals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count += 1
        except:
            continue
    for link in Favicon['internals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count += 1
        except:
            continue
    return count


def internal_redirection(Href, Link, Media, Form, CSS, Favicon):
    internals = h_internal(Href, Link, Media, Form, CSS, Favicon)
    if (internals > 0):
        return h_i_redirect(Href, Link, Media, Form, CSS, Favicon) / internals
    return 0


def h_e_redirect(Href, Link, Media, Form, CSS, Favicon):
    count = 0
    for link in Href['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count += 1
        except:
            continue
    for link in Link['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count += 1
        except:
            continue
    for link in Media['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count += 1
        except:
            continue
    for link in Form['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count += 1
        except:
            continue
    for link in CSS['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count += 1
        except:
            continue
    for link in Favicon['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count += 1
        except:
            continue
    return count


def external_redirection(Href, Link, Media, Form, CSS, Favicon):
    externals = h_external(Href, Link, Media, Form, CSS, Favicon)
    if (externals > 0):
        return h_e_redirect(Href, Link, Media, Form, CSS, Favicon) / externals
    return 0


def h_i_error(Href, Link, Media, Form, CSS, Favicon):
    count = 0
    for link in Href['internals']:
        try:
            if requests.get(link).status_code >= 400:
                count += 1
        except:
            continue
    for link in Link['internals']:
        try:
            if requests.get(link).status_code >= 400:
                count += 1
        except:
            continue
    for link in Media['internals']:
        try:
            if requests.get(link).status_code >= 400:
                count += 1
        except:
            continue
    for link in Form['internals']:
        try:
            if requests.get(link).status_code >= 400:
                count += 1
        except:
            continue
    for link in CSS['internals']:
        try:
            if requests.get(link).status_code >= 400:
                count += 1
        except:
            continue
    for link in Favicon['internals']:
        try:
            if requests.get(link).status_code >= 400:
                count += 1
        except:
            continue
    return count


def internal_errors(Href, Link, Media, Form, CSS, Favicon):
    internals = h_internal(Href, Link, Media, Form, CSS, Favicon)
    if (internals > 0):
        return h_i_error(Href, Link, Media, Form, CSS, Favicon) / internals
    return 0


def h_e_error(Href, Link, Media, Form, CSS, Favicon):
    count = 0
    for link in Href['externals']:
        try:
            if requests.get(link).status_code >= 400:
                count += 1
        except:
            continue
    for link in Link['externals']:
        try:
            if requests.get(link).status_code >= 400:
                count += 1
        except:
            continue
    for link in Media['externals']:
        try:
            if requests.get(link).status_code >= 400:
                count += 1
        except:
            continue
    for link in Form['externals']:
        try:
            if requests.get(link).status_code >= 400:
                count += 1
        except:
            continue
    for link in CSS['externals']:
        try:
            if requests.get(link).status_code >= 400:
                count += 1
        except:
            continue
    for link in Favicon['externals']:
        try:
            if requests.get(link).status_code >= 400:
                count += 1
        except:
            continue
    return count


def external_errors(Href, Link, Media, Form, CSS, Favicon):
    externals = h_external(Href, Link, Media, Form, CSS, Favicon)
    if (externals > 0):
        return h_e_error(Href, Link, Media, Form, CSS, Favicon) / externals
    return 0


def external_favicon(Favicon):
    if len(Favicon['externals']) > 0:
        return 1
    return 0


def internal_media(Media):
    total = len(Media['internals']) + len(Media['externals'])
    internals = len(Media['internals'])
    try:
        percentile = internals / float(total) * 100
    except:
        return 0
    return percentile


def external_media(Media):
    total = len(Media['internals']) + len(Media['externals'])
    externals = len(Media['externals'])
    try:
        percentile = externals / float(total) * 100
    except:
        return 0
    return percentile


def empty_title(Title):
    if Title:
        return 0
    return 1


def safe_anchor(Anchor):
    total = len(Anchor['safe']) + len(Anchor['unsafe'])
    unsafe = len(Anchor['unsafe'])
    try:
        percentile = unsafe / float(total) * 100
    except:
        return 0
    return percentile


def links_in_tags(Link):
    total = len(Link['internals']) + len(Link['externals'])
    internals = len(Link['internals'])
    try:
        percentile = internals / float(total) * 100
    except:
        return 0
    return percentile


def popup_window(content):
    if "prompt(" in str(content).lower():
        return 1
    else:
        return 0


def domain_in_title(domain, title):
    if domain.lower() in title.lower():
        return 0
    return 1


def domain_with_copyright(domain, content):
    try:
        m = re.search(u'(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN})', content)
        _copyright = content[m.span()[0] - 50:m.span()[0] + 50]
        if domain.lower() in _copyright.lower():
            return 0
        else:
            return 1
    except:
        return 0


def google_index(url):
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
    headers = {'User-Agent': user_agent}
    query = {'q': 'site:' + url}
    google = "https://www.google.com/search?" + urlencode(query)
    data = requests.get(google, headers=headers)
    data.encoding = 'ISO-8859-1'
    soup = BeautifulSoup(str(data.content), "html.parser")
    try:
        if 'Our systems have detected unusual traffic from your computer network.' in str(soup):
            return -1
        check = soup.find(id="rso").find("div").find("div").find("a")
        if check and check['href']:
            return 0
        else:
            return 1
    except AttributeError:
        return 1


def dns_record(domain):
    try:
        nameservers = dns.resolver.resolve(domain, 'NS')
        if len(nameservers) > 0:
            return 1
        else:
            return 0
    except Exception as e:
        print(f"Error fetching DNS records: {e}")
        return -1


def page_rank(key, domain):
    url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    try:
        request = requests.get(url, headers={'API-OPR': key})
        result = request.json()
        result = result['response'][0]['page_rank_integer']
        if result:
            return result
        else:
            return 0
    except:
        return -1


key = '8cs0c0kockg80s80o8kgcs0ogok4sck840s8ksk4'


def is_URL_accessible(url):
    print(f"Checking URL: {url}")
    page = None
    try:
        page = requests.get(url, timeout=5)
        print(f"Page status code: {page.status_code}")
    except Exception as e:
        print(f"Error accessing URL: {e}")
        parsed = urlparse(url)
        url = parsed.scheme + '://' + parsed.netloc
        if not parsed.netloc.startswith('www'):
            url = parsed.scheme + '://www.' + parsed.netloc
            try:
                page = requests.get(url, timeout=5)
                print(f"Retry page status code: {page.status_code}")
            except Exception as e:
                print(f"Retry error accessing URL: {e}")
                page = None
    if page and page.status_code == 200 and page.content not in ["b''", "b' '"]:
        print("URL is accessible")
        return True, url, page
    else:
        print("URL is not accessible")
        return False, None, None


def get_domain(url):
    o = urllib.parse.urlsplit(url)
    return o.hostname, tldextract.extract(url).domain, o.path


def getPageContent(url):
    parsed = urlparse(url)
    url = parsed.scheme + '://' + parsed.netloc
    try:
        page = requests.get(url)
    except:
        if not parsed.netloc.startswith('www'):
            url = parsed.scheme + '://www.' + parsed.netloc
            page = requests.get(url)
    if page.status_code != 200:
        return None, None
    else:
        return url, page.content


def extract_data_from_URL(hostname, content, domain, Href, Link, Anchor, Media, Form, CSS, Favicon, Title, Text):
    Null_format = ["", "#", "#nothing", "#doesnotexist", "#null", "#void", "#whatever",
                   "#content", "javascript::void(0)", "javascript::void(0);", "javascript::;", "javascript"]

    soup = BeautifulSoup(content, 'html.parser', from_encoding='iso-8859-1')

    for href in soup.find_all('a', href=True):
        dots = [x.start(0) for x in re.finditer(r'\.', href['href'])]
        if hostname in href['href'] or domain in href['href'] or len(dots) == 1 or not href['href'].startswith('http'):
            if "#" in href['href'] or "javascript" in href['href'].lower() or "mailto" in href['href'].lower():
                Anchor['unsafe'].append(href['href'])
            if not href['href'].startswith('http'):
                if not href['href'].startswith('/'):
                    Href['internals'].append(hostname + '/' + href['href'])
                elif href['href'] in Null_format:
                    Href['null'].append(href['href'])
                else:
                    Href['internals'].append(hostname + href['href'])
        else:
            Href['externals'].append(href['href'])
            Anchor['safe'].append(href['href'])

    for img in soup.find_all('img', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', img['src'])]
        if hostname in img['src'] or domain in img['src'] or len(dots) == 1 or not img['src'].startswith('http'):
            if not img['src'].startswith('http'):
                if not img['src'].startswith('/'):
                    Media['internals'].append(hostname + '/' + img['src'])
                elif img['src'] in Null_format:
                    Media['null'].append(img['src'])
                else:
                    Media['internals'].append(hostname + img['src'])
        else:
            Media['externals'].append(img['src'])

    for audio in soup.find_all('audio', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', audio['src'])]
        if hostname in audio['src'] or domain in audio['src'] or len(dots) == 1 or not audio['src'].startswith('http'):
            if not audio['src'].startswith('http'):
                if not audio['src'].startswith('/'):
                    Media['internals'].append(hostname + '/' + audio['src'])
                elif audio['src'] in Null_format:
                    Media['null'].append(audio['src'])
                else:
                    Media['internals'].append(hostname + audio['src'])
        else:
            Media['externals'].append(audio['src'])

    for embed in soup.find_all('embed', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', embed['src'])]
        if hostname in embed['src'] or domain in embed['src'] or len(dots) == 1 or not embed['src'].startswith('http'):
            if not embed['src'].startswith('http'):
                if not embed['src'].startswith('/'):
                    Media['internals'].append(hostname + '/' + embed['src'])
                elif embed['src'] in Null_format:
                    Media['null'].append(embed['src'])
                else:
                    Media['internals'].append(hostname + embed['src'])
        else:
            Media['externals'].append(embed['src'])

    for i_frame in soup.find_all('iframe', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', i_frame['src'])]
        if hostname in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1 or not i_frame['src'].startswith(
                'http'):
            if not i_frame['src'].startswith('http'):
                if not i_frame['src'].startswith('/'):
                    Media['internals'].append(hostname + '/' + i_frame['src'])
                elif i_frame['src'] in Null_format:
                    Media['null'].append(i_frame['src'])
                else:
                    Media['internals'].append(hostname + i_frame['src'])
        else:
            Media['externals'].append(i_frame['src'])

    for link in soup.findAll('link', href=True):
        dots = [x.start(0) for x in re.finditer(r'\.', link['href'])]
        if hostname in link['href'] or domain in link['href'] or len(dots) == 1 or not link['href'].startswith('http'):
            if not link['href'].startswith('http'):
                if not link['href'].startswith('/'):
                    Link['internals'].append(hostname + '/' + link['href'])
                elif link['href'] in Null_format:
                    Link['null'].append(link['href'])
                else:
                    Link['internals'].append(hostname + link['href'])
        else:
            Link['externals'].append(link['href'])

    for script in soup.find_all('script', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', script['src'])]
        if hostname in script['src'] or domain in script['src'] or len(dots) == 1 or not script['src'].startswith(
                'http'):
            if not script['src'].startswith('http'):
                if not script['src'].startswith('/'):
                    Link['internals'].append(hostname + '/' + script['src'])
                elif script['src'] in Null_format:
                    Link['null'].append(script['src'])
                else:
                    Link['internals'].append(hostname + script['src'])
        else:
            Link['externals'].append(link['href'])

    for link in soup.find_all('link', rel='stylesheet'):
        dots = [x.start(0) for x in re.finditer(r'\.', link['href'])]
        if hostname in link['href'] or domain in link['href'] or len(dots) == 1 or not link['href'].startswith('http'):
            if not link['href'].startswith('http'):
                if not link['href'].startswith('/'):
                    CSS['internals'].append(hostname + '/' + link['href'])
                elif link['href'] in Null_format:
                    CSS['null'].append(link['href'])
                else:
                    CSS['internals'].append(hostname + link['href'])
        else:
            CSS['externals'].append(link['href'])

    for style in soup.find_all('style', type='text/css'):
        try:
            start = str(style[0]).index('@import url(')
            end = str(style[0]).index(')')
            css = str(style[0])[start + 12:end]
            dots = [x.start(0) for x in re.finditer(r'\.', css)]
            if hostname in css or domain in css or len(dots) == 1 or not css.startswith('http'):
                if not css.startswith('http'):
                    if not css.startswith('/'):
                        CSS['internals'].append(hostname + '/' + css)
                    elif css in Null_format:
                        CSS['null'].append(css)
                    else:
                        CSS['internals'].append(hostname + css)
            else:
                CSS['externals'].append(css)
        except:
            continue

    for form in soup.findAll('form', action=True):
        dots = [x.start(0) for x in re.finditer(r'\.', form['action'])]
        if hostname in form['action'] or domain in form['action'] or len(dots) == 1 or not form['action'].startswith(
                'http'):
            if not form['action'].startswith('http'):
                if not form['action'].startswith('/'):
                    Form['internals'].append(hostname + '/' + form['action'])
                elif form['action'] in Null_format or form['action'] == 'about:blank':
                    Form['null'].append(form['action'])
                else:
                    Form['internals'].append(hostname + form['action'])
        else:
            Form['externals'].append(form['action'])

    for head in soup.find_all('head'):
        for head.link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer(r'\.', head.link['href'])]
            if hostname in head.link['href'] or len(dots) == 1 or domain in head.link['href'] or not head.link[
                'href'].startswith('http'):
                if not head.link['href'].startswith('http'):
                    if not head.link['href'].startswith('/'):
                        Favicon['internals'].append(hostname + '/' + head.link['href'])
                    elif head.link['href'] in Null_format:
                        Favicon['null'].append(head.link['href'])
                    else:
                        Favicon['internals'].append(hostname + head.link['href'])
            else:
                Favicon['externals'].append(head.link['href'])

        for head.link in soup.findAll('link', {'href': True, 'rel': True}):
            isicon = False
            if isinstance(head.link['rel'], list):
                for e_rel in head.link['rel']:
                    if (e_rel.endswith('icon')):
                        isicon = True
            else:
                if (head.link['rel'].endswith('icon')):
                    isicon = True
            if isicon:
                dots = [x.start(0) for x in re.finditer(r'\.', head.link['href'])]
                if hostname in head.link['href'] or len(dots) == 1 or domain in head.link['href'] or not head.link[
                    'href'].startswith('http'):
                    if not head.link['href'].startswith('http'):
                        if not head.link['href'].startswith('/'):
                            Favicon['internals'].append(hostname + '/' + head.link['href'])
                        elif head.link['href'] in Null_format:
                            Favicon['null'].append(head.link['href'])
                        else:
                            Favicon['internals'].append(hostname + head.link['href'])
                else:
                    Favicon['externals'].append(head.link['href'])

    try:
        Title = soup.title.string
    except:
        pass

    Text = soup.get_text()

    return Href, Link, Anchor, Media, Form, CSS, Favicon, Title, Text


def words_raw_extraction(domain, subdomain, path):
    w_domain = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", domain.lower())
    w_subdomain = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", subdomain.lower())
    w_path = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", path.lower())
    raw_words = w_domain + w_path + w_subdomain
    w_host = w_domain + w_subdomain
    raw_words = list(filter(None, raw_words))
    return raw_words, list(filter(None, w_host)), list(filter(None, w_path))


def extract_features(url):
    print("Starting feature extraction")
    Href = {'internals': [], 'externals': [], 'null': []}
    Link = {'internals': [], 'externals': [], 'null': []}
    Anchor = {'safe': [], 'unsafe': [], 'null': []}
    Media = {'internals': [], 'externals': [], 'null': []}
    Form = {'internals': [], 'externals': [], 'null': []}
    CSS = {'internals': [], 'externals': [], 'null': []}
    Favicon = {'internals': [], 'externals': [], 'null': []}
    Title = ''
    Text = ''

    print("Checking URL accessibility")
    state, iurl, page = is_URL_accessible(url)
    if state:
        print("URL is accessible")
        content = page.content
        hostname, domain, path = get_domain(url)
        extracted_domain = tldextract.extract(url)
        domain = extracted_domain.domain + '.' + extracted_domain.suffix
        subdomain = extracted_domain.subdomain
        tmp = url[url.find(extracted_domain.suffix):len(url)]
        pth = tmp.partition("/")
        path = pth[1] + pth[2]
        words_raw, words_raw_host, words_raw_path = words_raw_extraction(extracted_domain.domain, subdomain, pth[2])
        tld = extracted_domain.suffix
        parsed = urlparse(url)
        scheme = parsed.scheme

        print("Extracting data from URL")
        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_href = executor.submit(extract_data_from_URL, hostname, content, domain, Href, Link, Anchor,
                                              Media, Form, CSS, Favicon, Title, Text)
                Href, Link, Anchor, Media, Form, CSS, Favicon, Title, Text = future_href.result()
        except Exception as e:
            print(f"Error in extract_data_from_URL: {e}")
            return None

        print("Calculating features")
        try:
            row = [[url_length(url),
                    url_length(hostname),
                    having_ip_address(url),
                    count_dots(url),
                    count_hyphens(url),
                    count_at(url),
                    count_exclamation(url),
                    count_and(url),
                    count_or(url),
                    count_underscore(url),
                    count_tilde(url),
                    count_percentage(url),
                    count_slash(url),
                    count_star(url),
                    count_colon(url),
                    count_comma(url),
                    check_www(words_raw),
                    check_com(words_raw),
                    count_double_slash(url),
                    count_http_token(path),
                    https_token(scheme),
                    ratio_digits(url),
                    ratio_digits(hostname),
                    tld_in_path(tld, path),
                    tld_in_subdomain(tld, subdomain),
                    abnormal_subdomain(url),
                    count_subdomain(url),
                    prefix_suffix(url),
                    shortening_service(url),
                    count_external_redirection(page, domain),
                    length_word_raw(words_raw),
                    char_repeat(words_raw),
                    shortest_word_length(words_raw),
                    shortest_word_length(words_raw_host),
                    shortest_word_length(words_raw_path),
                    longest_word_length(words_raw),
                    longest_word_length(words_raw_host),
                    longest_word_length(words_raw_path),
                    average_word_length(words_raw),
                    average_word_length(words_raw_host),
                    average_word_length(words_raw_path),
                    phish_hints(url),
                    domain_in_brand(extracted_domain.domain),
                    brand_in_path(extracted_domain.domain, subdomain),
                    brand_in_path(extracted_domain.domain, path),
                    suspicious_tld(tld),
                    statistical_report(url, domain),
                    nb_hyperlinks(content),
                    internal_hyperlinks(content, Href, Link, Media, Form, CSS, Favicon),
                    external_hyperlinks(content, Href, Link, Media, Form, CSS, Favicon),
                    external_css(CSS),
                    internal_redirection(Href, Link, Media, Form, CSS, Favicon),
                    external_redirection(Href, Link, Media, Form, CSS, Favicon),
                    external_errors(Href, Link, Media, Form, CSS, Favicon),
                    external_favicon(Favicon),
                    links_in_tags(Link),
                    internal_media(Media),
                    external_media(Media),
                    popup_window(Text),
                    safe_anchor(Anchor),
                    empty_title(Title),
                    domain_in_title(extracted_domain.domain, Title),
                    domain_with_copyright(extracted_domain.domain, Text),
                    dns_record(domain),
                    google_index(url),
                    page_rank(key, domain)]]

            print("Feature extraction completed successfully")
            return row
        except Exception as e:
            print(f"Error calculating features: {e}")
            return None
    else:
        print("URL is not accessible")
        return None


@app.get("/add-url", response_class=HTMLResponse)
async def add_url_form(request: Request):
    return templates.TemplateResponse("add_url.html", {"request": request})


@app.get("/view-urls", response_class=HTMLResponse)
async def view_urls(request: Request):
    db = SessionLocal()
    urls = db.query(URL).all()
    return templates.TemplateResponse("view_urls.html", {"request": request, "urls": urls})


@app.post("/submit-url", response_class=HTMLResponse)
async def submit_url(request: Request, url: str = Form(...)):
    db = SessionLocal()
    features = extract_features(url)
    if features is None:
        raise HTTPException(status_code=400, detail="Error extracting features from URL")

    url_data = URL(
        url=url,
        length_url=features[0][0],
        length_hostname=features[0][1],
        ip=features[0][2],
        nb_dots=features[0][3],
        nb_hyphens=features[0][4],
        nb_at=features[0][5],
        nb_qm=features[0][6],
        nb_and=features[0][7],
        nb_or=features[0][8],
        nb_underscore=features[0][9],
        nb_tilde=features[0][10],
        nb_percent=features[0][11],
        nb_slash=features[0][12],
        nb_star=features[0][13],
        nb_colon=features[0][14],
        nb_comma=features[0][15],
        nb_www=features[0][16],
        nb_com=features[0][17],
        nb_dslash=features[0][18],
        http_in_path=features[0][19],
        https_token=features[0][20],
        ratio_digits_url=features[0][21],
        ratio_digits_host=features[0][22],
        tld_in_path=features[0][23],
        tld_in_subdomain=features[0][24],
        abnormal_subdomain=features[0][25],
        nb_subdomains=features[0][26],
        prefix_suffix=features[0][27],
        shortening_service=features[0][28],
        nb_external_redirection=features[0][29],
        length_words_raw=features[0][30],
        char_repeat=features[0][31],
        shortest_words_raw=features[0][32],
        shortest_word_host=features[0][33],
        shortest_word_path=features[0][34],
        longest_words_raw=features[0][35],
        longest_word_host=features[0][36],
        longest_word_path=features[0][37],
        avg_words_raw=features[0][38],
        avg_word_host=features[0][39],
        avg_word_path=features[0][40],
        phish_hints=features[0][41],
        domain_in_brand=features[0][42],
        brand_in_subdomain=features[0][43],
        brand_in_path=features[0][44],
        suspicious_tld=features[0][45],
        statistical_report=features[0][46],
        nb_hyperlinks=features[0][47],
        ratio_intHyperlinks=features[0][48],
        ratio_extHyperlinks=features[0][49],
        nb_extCSS=features[0][50],
        ratio_intRedirection=features[0][51],
        ratio_extRedirection=features[0][52],
        ratio_extErrors=features[0][53],
        external_favicon=features[0][54],
        links_in_tags=features[0][55],
        ratio_intMedia=features[0][56],
        ratio_extMedia=features[0][57],
        popup_window=features[0][58],
        safe_anchor=features[0][59],
        empty_title=features[0][60],
        domain_in_title=features[0][61],
        domain_with_copyright=features[0][62],
        dns_record=features[0][63],
        google_index=features[0][64],
        page_rank=features[0][65]
    )

    db.add(url_data)
    db.commit()
    db.refresh(url_data)

    # Start retraining in a separate thread
    threading.Thread(target=retrain_model_thread).start()

    return templates.TemplateResponse("success.html", {"request": request, "url": url, "retraining": True})


retraining_status = {"status": "idle"}


def retrain_model_thread():
    global retraining_status
    retraining_status["status"] = "in_progress"
    db = SessionLocal()
    try:
        urls = db.query(URL).all()
        if not urls:
            retraining_status["status"] = "no_data"
            return "No data available for retraining"

        data = []
        labels = []
        for url in urls:
            features = [
                url.length_url, url.length_hostname, url.ip, url.nb_dots, url.nb_hyphens, url.nb_at, url.nb_qm,
                url.nb_and, url.nb_or, url.nb_underscore, url.nb_tilde, url.nb_percent, url.nb_slash, url.nb_star,
                url.nb_colon, url.nb_comma, url.nb_www, url.nb_com, url.nb_dslash, url.http_in_path, url.https_token,
                url.ratio_digits_url, url.ratio_digits_host, url.tld_in_path, url.tld_in_subdomain,
                url.abnormal_subdomain,
                url.nb_subdomains, url.prefix_suffix, url.shortening_service, url.nb_external_redirection,
                url.length_words_raw, url.char_repeat, url.shortest_words_raw, url.shortest_word_host,
                url.shortest_word_path,
                url.longest_words_raw, url.longest_word_host, url.longest_word_path, url.avg_words_raw,
                url.avg_word_host,
                url.avg_word_path, url.phish_hints, url.domain_in_brand, url.brand_in_subdomain, url.brand_in_path,
                url.suspicious_tld, url.statistical_report, url.nb_hyperlinks, url.ratio_intHyperlinks,
                url.ratio_extHyperlinks,
                url.nb_extCSS, url.ratio_intRedirection, url.ratio_extRedirection, url.ratio_extErrors,
                url.external_favicon,
                url.links_in_tags, url.ratio_intMedia, url.ratio_extMedia, url.popup_window, url.safe_anchor,
                url.empty_title,
                url.domain_in_title, url.domain_with_copyright, url.dns_record, url.google_index, url.page_rank
            ]
            data.append(features)
            labels.append(1 if "phishing" in url.url else 0)  # Assuming the label can be inferred from the URL content

        df = pd.DataFrame(data, columns=feature_names)
        labels = np.array(labels)

        model.fit(df, labels)
        joblib.dump(model, model_path)

        retraining_status["status"] = "completed"
        return "Model retrained and updated successfully"

    except Exception as e:
        retraining_status["status"] = "error"
        return f"Error retraining model: {e}"
    finally:
        db.close()


@app.get("/retrain-status")
async def retrain_status():
    return retraining_status


@app.post("/predict")
def predict(request: URLRequest):
    if model is None or features is None:
        raise HTTPException(status_code=500, detail="Model or features not loaded")

    try:
        url_features = extract_features(request.url)
        if url_features is None:
            return {"url": request.url, "prediction": "phishing"}

        url_features_df = pd.DataFrame(url_features, columns=feature_names)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error extracting features: {e}")

    try:
        prediction = model.predict(url_features_df)
        result = "phishing" if prediction[0] == 1 else "legitimate"
        return {"url": request.url, "prediction": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error making prediction: {e}")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
