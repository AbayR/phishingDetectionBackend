import re
import Levenshtein
import socket
import requests
from bs4 import BeautifulSoup
import requests
import dns.resolver
from urllib.parse import urlencode, urlparse
import pandas as pd 
import urllib.parse
import tldextract
import json
import csv
import os


###############################################################################
# URL-BASED FEATURES
###############################################################################


HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']

allbrand_txt = open("allbrands.txt", "r")

def __txt_to_list(txt_object):
    list = []
    for line in txt_object:
        list.append(line.strip())
    txt_object.close()
    return list

allbrand = __txt_to_list(allbrand_txt)


def having_ip_address(url):
    match = re.search(
        r'(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        r'([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        r'((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        r'[0-9a-fA-F]{7}', url)  # Ipv6
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
                      r'tr\.im|link\.zip\.net',
                      full_url)
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
    list=[x.start(0) for x in re.finditer('//', full_url)]
    if list[len(list)-1]>6:
        return 1
    else:
        return 0
    # return full_url.count('//')


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
    return len(re.sub("[^0-9]", "", hostname))/len(hostname)


def count_digits(line):
    return len(re.sub("[^0-9]", "", line))


def phish_hints(url_path):
    count = 0
    for hint in HINTS:
        count += url_path.lower().count(hint)
    return count


def tld_in_path(tld, path):
    if path.lower().count(tld)>0:
        return 1
    return 0
    

def tld_in_subdomain(tld, subdomain):
    if subdomain.count(tld)>0:
        return 1
    return 0


def tld_in_bad_position(tld, subdomain, path):
    if tld_in_path(tld, path)== 1 or tld_in_subdomain(tld, subdomain)==1:
        return 1
    return 0


def abnormal_subdomain(url):
    if re.search(r'(http[s]?://(w[w]?|\d))([w]?(\d|-))',url):
        return 1
    return 0
    

def count_redirection(page):
    return len(page.history)
    

def count_external_redirection(page, domain):
    count = 0
    if len(page.history) == 0:
        return 0
    else:
        for i, response in enumerate(page.history,1):
            if domain.lower() not in response.url.lower():
                count+=1          
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
        return  sum(list(repeat.values()))


def domain_in_brand(domain):
        
    if domain in allbrand:
        return 1
    else:
        return 0


def brand_in_path(domain,path):
    for b in allbrand:
        if '.'+b+'.' in path and b not in domain:
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
    if len(words_raw) ==0:
        return 0
    return sum(len(word) for word in words_raw) / len(words_raw)


def longest_word_length(words_raw):
    if len(words_raw) ==0:
        return 0
    return max(len(word) for word in words_raw) 


def shortest_word_length(words_raw):
    if len(words_raw) ==0:
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
    url_match=re.search(r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
    try:
        ip_address=socket.gethostbyname(domain)
        ip_match=re.search(r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                           r'107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                           r'118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                           r'216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                           r'34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                           r'216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)
        if url_match or ip_match:
            return 1
        else:
            return 0
    except:
        return 2


suspicious_tlds = ['fit','tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu', 'online', 'click', # Spamhaus
        'country', 'stream', 'download', 'xin', 'racing', 'jetzt',
        'ren', 'mom', 'party', 'review', 'trade', 'accountants', 
        'science', 'work', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win',
        'accountant', 'realtor', 'top', 'christmas', 'gdn', # Shady Top-Level Domains
        'link', # Blue Coat Systems
        'asia', 'club', 'la', 'ae', 'exposed', 'pe', 'go.id', 'rs', 'k12.pa.us', 'or.kr',
        'ce.ke', 'audio', 'gob.pe', 'gov.az', 'website', 'bj', 'mx', 'media', 'sa.gov.au' # statistics
        ]


def suspicious_tld(tld):
   if tld in suspicious_tlds:
       return 1
   return 0
    

###############################################################################
# CONTENT-BASED FEATURES
###############################################################################

def nb_hyperlinks(dom):
    soup = BeautifulSoup(dom, 'html.parser')
    return len(soup.find_all(href=True)) + len(soup.find_all(src=True))

def h_total(dom):
    return nb_hyperlinks(dom)

def h_internal(Href, Link, Media, Form, CSS, Favicon):
    return len(Href['internals']) + len(Link['internals']) + len(Media['internals']) +\
           len(Form['internals']) + len(CSS['internals']) + len(Favicon['internals'])


def internal_hyperlinks(dom, Href, Link, Media, Form, CSS, Favicon):
    total = h_total(dom)
    if total == 0:
        return 0
    else :
        return h_internal(Href, Link, Media, Form, CSS, Favicon)/total


def h_external(Href, Link, Media, Form, CSS, Favicon):
    return len(Href['externals']) + len(Link['externals']) + len(Media['externals']) +\
           len(Form['externals']) + len(CSS['externals']) + len(Favicon['externals'])
           
           
def external_hyperlinks(dom, Href, Link, Media, Form, CSS, Favicon):
    total = h_total(dom)
    if total == 0:
        return 0
    else :
        return h_external(Href, Link, Media, Form, CSS, Favicon)/total


def external_css(CSS):
    return len(CSS['externals'])
    

def h_i_redirect(Href, Link, Media, Form, CSS, Favicon):
    count = 0
    for link in Href['internals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue
    for link in Link['internals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue
    for link in Media['internals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue
    for link in Form['internals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue
    for link in CSS['internals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue
    for link in Favicon['internals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue
    return count

def internal_redirection(Href, Link, Media, Form, CSS, Favicon):
    internals = h_internal(Href, Link, Media, Form, CSS, Favicon)
    if (internals>0):
        return h_i_redirect(Href, Link, Media, Form, CSS, Favicon)/internals
    return 0


def h_e_redirect(Href, Link, Media, Form, CSS, Favicon):
    count = 0
    for link in Href['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue
    for link in Link['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue
    for link in Media['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue
    for link in Media['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue 
    for link in Form['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue    
    for link in CSS['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue    
    for link in Favicon['externals']:
        try:
            r = requests.get(link)
            if len(r.history) > 0:
                count+=1
        except:
            continue    
    return count

def external_redirection(Href, Link, Media, Form, CSS, Favicon):
    externals = h_external(Href, Link, Media, Form, CSS, Favicon)
    if (externals>0):
        return h_e_redirect(Href, Link, Media, Form, CSS, Favicon)/externals
    return 0


def h_i_error(Href, Link, Media, Form, CSS, Favicon):
    count = 0
    for link in Href['internals']:
        try:
            if requests.get(link).status_code >=400:
                count+=1
        except:
            continue
    for link in Link['internals']:
        try:
            if requests.get(link).status_code >=400:
                count+=1
        except:
            continue
    for link in Media['internals']:
        try:
            if requests.get(link).status_code >=400:
                count+=1
        except:
            continue
    for link in Form['internals']:
        try:
            if requests.get(link).status_code >=400:
                count+=1
        except:
            continue
    for link in CSS['internals']:
        try:
            if requests.get(link).status_code >=400:
                count+=1
        except:
            continue  
    for link in Favicon['internals']:
        try:
            if requests.get(link).status_code >=400:
                count+=1
        except:
            continue
    return count

def internal_errors(Href, Link, Media, Form, CSS, Favicon):
    internals = h_internal(Href, Link, Media, Form, CSS, Favicon)
    if (internals>0):
        return h_i_error(Href, Link, Media, Form, CSS, Favicon)/internals
    return 0


def h_e_error(Href, Link, Media, Form, CSS, Favicon):
    count = 0
    for link in Href['externals']:
        try:
            if requests.get(link).status_code >=400:
                count+=1
        except:
            continue
    for link in Link['externals']:
        try:
            if requests.get(link).status_code >=400:
                count+=1
        except:
            continue
    for link in Media['externals']:
        try:
            if requests.get(link).status_code >=400:
                count+=1
        except:
            continue
    for link in Form['externals']:
        try:
            if requests.get(link).status_code >=400:
                count+=1
        except:
            continue
    for link in CSS['externals']:
        try:
            if requests.get(link).status_code >=400:
                count+=1
        except:
            continue
    for link in Favicon['externals']:
        try:
            if requests.get(link).status_code >=400:
                count+=1
        except:
            continue
    return count


def external_errors(Href, Link, Media, Form, CSS, Favicon):
    externals = h_external(Href, Link, Media, Form, CSS, Favicon)
    if (externals>0):
        return h_e_error(Href, Link, Media, Form, CSS, Favicon)/externals
    return 0


def external_favicon(Favicon):
    if len(Favicon['externals'])>0:
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
    total = len(Anchor['safe']) +  len(Anchor['unsafe'])
    unsafe = len(Anchor['unsafe'])
    try:
        percentile = unsafe / float(total) * 100
    except:
        return 0
    return percentile 


def links_in_tags(Link):
    total = len(Link['internals']) +  len(Link['externals'])
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
        _copyright = content[m.span()[0]-50:m.span()[0]+50]
        if domain.lower() in _copyright.lower():
            return 0
        else:
            return 1 
    except:
        return 0



# EXTERNAL SERVICES BASED FEATURES

def google_index(url):
    #time.sleep(.6)
    user_agent =  'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
    headers = {'User-Agent' : user_agent}
    query = {'q': 'site:' + url}
    google = "https://www.google.com/search?" + urlencode(query)
    data = requests.get(google, headers=headers)
    data.encoding = 'ISO-8859-1'
    soup = BeautifulSoup(str(data.content), "html.parser")
    try:
        if 'Our systems have detected unusual traffic from your computer network.' in str(soup):
            return -1
        check = soup.find(id="rso").find("div").find("div").find("a")
        #print(check)
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
        request = requests.get(url, headers={'API-OPR':key})
        result = request.json()
        result = result['response'][0]['page_rank_integer']
        if result:
            return result
        else:
            return 0
    except:
        return -1
    


#HEADERS

headers = [ 'length_url',                                  
            'length_hostname',
            'ip',
            'nb_dots',
            'nb_hyphens',
            'nb_at',
            'nb_qm',
            'nb_and',
            'nb_or',                 
            'nb_underscore',
            'nb_tilde',
            'nb_percent',
            'nb_slash',
            'nb_star',
            'nb_colon',
            'nb_comma',
            'nb_www',
            'nb_com',
            'nb_dslash',
            'http_in_path',
            'https_token',
            'ratio_digits_url',
            'ratio_digits_host',
            'tld_in_path',
            'tld_in_subdomain',
            'abnormal_subdomain',
            'nb_subdomains',
            'prefix_suffix',
            'shortening_service',
            'nb_external_redirection',
            'length_words_raw',
            'char_repeat',
            'shortest_words_raw',
            'shortest_word_host',
            'shortest_word_path',
            'longest_words_raw',
            'longest_word_host',
            'longest_word_path',
            'avg_words_raw',
            'avg_word_host',
            'avg_word_path',
            'phish_hints',
            'domain_in_brand',
            'brand_in_subdomain',
            'brand_in_path',
            'suspicious_tld',
            'statistical_report',

            'nb_hyperlinks', 
            'ratio_intHyperlinks',
            'ratio_extHyperlinks',
            'nb_extCSS',
            'ratio_intRedirection',
            'ratio_extRedirection',
            'ratio_extErrors',
            'external_favicon',
            'links_in_tags',
            'ratio_intMedia',
            'ratio_extMedia',
            'popup_window',
            'safe_anchor', 
            'empty_title', 
            'domain_in_title',
            'domain_with_copyright',

            'dns_record',
            'google_index',
            'page_rank']


######################################################################################################
# EXTRACTION
######################################################################################################

key = '8cs0c0kockg80s80o8kgcs0ogok4sck840s8ksk4'

def is_URL_accessible(url):
    page = None
    try:
        page = requests.get(url, timeout=5)   
    except:
        parsed = urlparse(url)
        url = parsed.scheme+'://'+parsed.netloc
        if not parsed.netloc.startswith('www'):
            url = parsed.scheme+'://www.'+parsed.netloc
            try:
                page = requests.get(url, timeout=5)
            except:
                page = None
    if page and page.status_code == 200 and page.content not in ["b''", "b' '"]:
        return True, url, page
    else:
        return False, None, None

def get_domain(url):
    o = urllib.parse.urlsplit(url)
    return o.hostname, tldextract.extract(url).domain, o.path


def getPageContent(url):
    parsed = urlparse(url)
    url = parsed.scheme+'://'+parsed.netloc
    try:
        page = requests.get(url)
    except:
        if not parsed.netloc.startswith('www'):
            url = parsed.scheme+'://www.'+parsed.netloc
            page = requests.get(url)
    if page.status_code != 200:
        return None, None
    else:    
        return url, page.content
 

#################################################################################################################################
# DATA EXTRACTION
#################################################################################################################################

def extract_data_from_URL(hostname, content, domain, Href, Link, Anchor, Media, Form, CSS, Favicon, Title, Text):
    Null_format = ["", "#", "#nothing", "#doesnotexist", "#null", "#void", "#whatever",
               "#content", "javascript::void(0)", "javascript::void(0);", "javascript::;", "javascript"]

    soup = BeautifulSoup(content, 'html.parser', from_encoding='iso-8859-1')

    # collect all external and internal hrefs from url
    for href in soup.find_all('a', href=True):
        dots = [x.start(0) for x in re.finditer(r'\.', href['href'])]
        if hostname in href['href'] or domain in href['href'] or len(dots) == 1 or not href['href'].startswith('http'):
            if "#" in href['href'] or "javascript" in href['href'].lower() or "mailto" in href['href'].lower():
                 Anchor['unsafe'].append(href['href']) 
            if not href['href'].startswith('http'):
                if not href['href'].startswith('/'):
                    Href['internals'].append(hostname+'/'+href['href']) 
                elif href['href'] in Null_format:
                    Href['null'].append(href['href'])  
                else:
                    Href['internals'].append(hostname+href['href'])   
        else:
            Href['externals'].append(href['href'])
            Anchor['safe'].append(href['href'])

    # collect all media src tags
    for img in soup.find_all('img', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', img['src'])]
        if hostname in img['src'] or domain in img['src'] or len(dots) == 1 or not img['src'].startswith('http'):
            if not img['src'].startswith('http'):
                if not img['src'].startswith('/'):
                    Media['internals'].append(hostname+'/'+img['src']) 
                elif img['src'] in Null_format:
                    Media['null'].append(img['src'])  
                else:
                    Media['internals'].append(hostname+img['src'])   
        else:
            Media['externals'].append(img['src'])
           
    
    for audio in soup.find_all('audio', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', audio['src'])]
        if hostname in audio['src'] or domain in audio['src'] or len(dots) == 1 or not audio['src'].startswith('http'):
             if not audio['src'].startswith('http'):
                if not audio['src'].startswith('/'):
                    Media['internals'].append(hostname+'/'+audio['src']) 
                elif audio['src'] in Null_format:
                    Media['null'].append(audio['src'])  
                else:
                    Media['internals'].append(hostname+audio['src'])   
        else:
            Media['externals'].append(audio['src'])
            
    for embed in soup.find_all('embed', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', embed['src'])]
        if hostname in embed['src'] or domain in embed['src'] or len(dots) == 1 or not embed['src'].startswith('http'):
             if not embed['src'].startswith('http'):
                if not embed['src'].startswith('/'):
                    Media['internals'].append(hostname+'/'+embed['src']) 
                elif embed['src'] in Null_format:
                    Media['null'].append(embed['src'])  
                else:
                    Media['internals'].append(hostname+embed['src'])   
        else:
            Media['externals'].append(embed['src'])
           
    for i_frame in soup.find_all('iframe', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', i_frame['src'])]
        if hostname in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1 or not i_frame['src'].startswith('http'):
            if not i_frame['src'].startswith('http'):
                if not i_frame['src'].startswith('/'):
                    Media['internals'].append(hostname+'/'+i_frame['src']) 
                elif i_frame['src'] in Null_format:
                    Media['null'].append(i_frame['src'])  
                else:
                    Media['internals'].append(hostname+i_frame['src'])   
        else: 
            Media['externals'].append(i_frame['src'])
           

    # collect all link tags
    for link in soup.findAll('link', href=True):
        dots = [x.start(0) for x in re.finditer(r'\.', link['href'])]
        if hostname in link['href'] or domain in link['href'] or len(dots) == 1 or not link['href'].startswith('http'):
            if not link['href'].startswith('http'):
                if not link['href'].startswith('/'):
                    Link['internals'].append(hostname+'/'+link['href']) 
                elif link['href'] in Null_format:
                    Link['null'].append(link['href'])  
                else:
                    Link['internals'].append(hostname+link['href'])   
        else:
            Link['externals'].append(link['href'])

    for script in soup.find_all('script', src=True):
        dots = [x.start(0) for x in re.finditer(r'\.', script['src'])]
        if hostname in script['src'] or domain in script['src'] or len(dots) == 1 or not script['src'].startswith('http'):
            if not script['src'].startswith('http'):
                if not script['src'].startswith('/'):
                    Link['internals'].append(hostname+'/'+script['src']) 
                elif script['src'] in Null_format:
                    Link['null'].append(script['src'])  
                else:
                    Link['internals'].append(hostname+script['src'])   
        else:
            Link['externals'].append(link['href'])
           
            
    # collect all css
    for link in soup.find_all('link', rel='stylesheet'):
        dots = [x.start(0) for x in re.finditer(r'\.', link['href'])]
        if hostname in link['href'] or domain in link['href'] or len(dots) == 1 or not link['href'].startswith('http'):
            if not link['href'].startswith('http'):
                if not link['href'].startswith('/'):
                    CSS['internals'].append(hostname+'/'+link['href']) 
                elif link['href'] in Null_format:
                    CSS['null'].append(link['href'])  
                else:
                    CSS['internals'].append(hostname+link['href'])   
        else:
            CSS['externals'].append(link['href'])
    
    for style in soup.find_all('style', type='text/css'):
        try: 
            start = str(style[0]).index('@import url(')
            end = str(style[0]).index(')')
            css = str(style[0])[start+12:end]
            dots = [x.start(0) for x in re.finditer(r'\.', css)]
            if hostname in css or domain in css or len(dots) == 1 or not css.startswith('http'):
                if not css.startswith('http'):
                    if not css.startswith('/'):
                        CSS['internals'].append(hostname+'/'+css) 
                    elif css in Null_format:
                        CSS['null'].append(css)  
                    else:
                        CSS['internals'].append(hostname+css)   
            else: 
                CSS['externals'].append(css)
        except:
            continue
            
    # collect all form actions
    for form in soup.findAll('form', action=True):
        dots = [x.start(0) for x in re.finditer(r'\.', form['action'])]
        if hostname in form['action'] or domain in form['action'] or len(dots) == 1 or not form['action'].startswith('http'):
            if not form['action'].startswith('http'):
                if not form['action'].startswith('/'):
                    Form['internals'].append(hostname+'/'+form['action']) 
                elif form['action'] in Null_format or form['action'] == 'about:blank':
                    Form['null'].append(form['action'])  
                else:
                    Form['internals'].append(hostname+form['action'])   
        else:
            Form['externals'].append(form['action'])
            

    # collect all link tags
    for head in soup.find_all('head'):
        for head.link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer(r'\.', head.link['href'])]
            if hostname in head.link['href'] or len(dots) == 1 or domain in head.link['href'] or not head.link['href'].startswith('http'):
                if not head.link['href'].startswith('http'):
                    if not head.link['href'].startswith('/'):
                        Favicon['internals'].append(hostname+'/'+head.link['href']) 
                    elif head.link['href'] in Null_format:
                        Favicon['null'].append(head.link['href'])  
                    else:
                        Favicon['internals'].append(hostname+head.link['href'])   
            else:
                Favicon['externals'].append(head.link['href'])
                
        for head.link in soup.findAll('link', {'href': True, 'rel':True}):
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
                 if hostname in head.link['href'] or len(dots) == 1 or domain in head.link['href'] or not head.link['href'].startswith('http'):
                     if not head.link['href'].startswith('http'):
                        if not head.link['href'].startswith('/'):
                            Favicon['internals'].append(hostname+'/'+head.link['href']) 
                        elif head.link['href'] in Null_format:
                            Favicon['null'].append(head.link['href'])  
                        else:
                            Favicon['internals'].append(hostname+head.link['href'])   
                 else:
                     Favicon['externals'].append(head.link['href'])

          
    # get page title
    try:
        Title = soup.title.string
    except:
        pass
    
    # get content text
    Text = soup.get_text()
    
    return Href, Link, Anchor, Media, Form, CSS, Favicon, Title, Text


#################################################################################################################################
#              Calculate features from extracted data
#################################################################################################################################


def extract_features(url):
    
    def words_raw_extraction(domain, subdomain, path):
        w_domain = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", domain.lower())
        w_subdomain = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", subdomain.lower())   
        w_path = re.split(r"\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", path.lower())
        raw_words = w_domain + w_path + w_subdomain
        w_host = w_domain + w_subdomain
        raw_words = list(filter(None,raw_words))
        return raw_words, list(filter(None,w_host)), list(filter(None,w_path))

    
    Href = {'internals':[], 'externals':[], 'null':[]}
    Link = {'internals':[], 'externals':[], 'null':[]}
    Anchor = {'safe':[], 'unsafe':[], 'null':[]}
    Media = {'internals':[], 'externals':[], 'null':[]}
    Form = {'internals':[], 'externals':[], 'null':[]}
    CSS = {'internals':[], 'externals':[], 'null':[]}
    Favicon = {'internals':[], 'externals':[], 'null':[]}
    Title =''
    Text= ''
    state, iurl, page = is_URL_accessible(url)
    if state:
        content = page.content
        hostname, domain, path = get_domain(url)
        extracted_domain = tldextract.extract(url)
        domain = extracted_domain.domain+'.'+extracted_domain.suffix
        subdomain = extracted_domain.subdomain
        tmp = url[url.find(extracted_domain.suffix):len(url)]
        pth = tmp.partition("/")
        path = pth[1] + pth[2]
        words_raw, words_raw_host, words_raw_path= words_raw_extraction(extracted_domain.domain, subdomain, pth[2])
        tld = extracted_domain.suffix
        parsed = urlparse(url)
        scheme = parsed.scheme
        
        Href, Link, Anchor, Media, Form, CSS, Favicon, Title, Text = extract_data_from_URL(hostname, content, domain, Href, Link, Anchor, Media, Form, CSS, Favicon, Title, Text)

        row = [[# url-based features
               url_length(url),
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
               brand_in_path(extracted_domain.domain,subdomain),
               brand_in_path(extracted_domain.domain,path),
               suspicious_tld(tld),
               statistical_report(url, domain),

               
               # # # content-based features
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
                 
                # # # thirs-party-based features
                dns_record(domain),
                google_index(url),
                page_rank(key,domain)]]

        return row
    return None

df = pd.DataFrame()

def generate_external_dataset(url):
    try:
        res = extract_features(url)
    except Exception as e:
        print('Exception occured: ', e)
        res = None

    if res!=None:
        df = pd.DataFrame(res, columns = [headers])
        return df
    else:
        print('Result is None')


print(generate_external_dataset('https://google.com'))
