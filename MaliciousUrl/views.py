from django.shortcuts import render
from urllib.parse import urlparse
from Malicious.models import urls
def home(request):    
    return render(request, 'index.html')
def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0
def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1


def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits
def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters
def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

import re
#Use of IP or not in domain
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return -1
    else:
        # print 'No matching pattern found'
        return 1

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return -1
    else:
        return 1

def Check(uncheckedurl):
    import pickle
    rfc = pickle.load(open("MaliciousUrl/MaliciousModel.sav", "rb"))
    import numpy as np
    import pandas as pd
    from urllib.parse import urlparse
    from tld import get_tld
    import os.path
    import sklearn
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split

    data = {'url' : [uncheckedurl]}
    main = pd.DataFrame(data,columns = ['url'])
    main['Url Length'] = main['url'].apply(lambda i: len(str(i)))
    main['host length'] = main['url'].apply(lambda i: len(urlparse(i).netloc))
    main['path length'] = main['url'].apply(lambda i: len(urlparse(i).path))
    main['First Dir length'] = main['url'].apply(lambda i: fd_length(i))
    main['tld'] = main['url'].apply(lambda i: get_tld(i,fail_silently=True))
    main=main.rename_axis('Index')
    main['tld length'] = main['tld'].apply(lambda i: tld_length(i))
    main.drop('tld',axis = 1,inplace=True)
    main['count-'] = main['url'].apply(lambda i: i.count('-'))
    main['count@'] = main['url'].apply(lambda i: i.count('@'))
    main['count?'] = main['url'].apply(lambda i: i.count('?'))
    main['count%'] = main['url'].apply(lambda i: i.count('%'))
    main['count.'] = main['url'].apply(lambda i: i.count('.'))
    main['count='] = main['url'].apply(lambda i: i.count('='))
    main['count-http'] = main['url'].apply(lambda i : i.count('http'))
    main['count-https'] = main['url'].apply(lambda i : i.count('https'))
    main['count-www'] = main['url'].apply(lambda i: i.count('www'))
    main['count-digits']= main['url'].apply(lambda i: digit_count(i))
    main['count-letters']= main['url'].apply(lambda i: letter_count(i))
    main['count_dir'] = main['url'].apply(lambda i: no_of_dir(i))
    main['use_of_ip'] = main['url'].apply(lambda i: having_ip_address(i))
    main['short_url'] = main['url'].apply(lambda i: shortening_service(i))
    x = main[['host length',
            'path length', 'First Dir length', 'tld length', 'count-', 'count@', 'count?',
            'count%', 'count.', 'count=', 'count-http','count-https', 'count-www', 'count-digits',
            'count-letters', 'count_dir', 'use_of_ip']]
    rfc_predictions = rfc.predict(x)

    if rfc_predictions == 0:
            return "Not Malicious"
    if rfc_predictions == 1:
            return "Malicious"

import requests
def result(request):
    try:
        uncheckedurl = request.GET['uncheckedurl']
        Name = request.GET['Name']
        uncheckedurls = requests.get(uncheckedurl)
        if uncheckedurls.status_code == 200:
            url = urls()
            url.Name = request.GET.get('Name',None)
            url.UrlName = request.GET.get('uncheckedurl',None)
            result = Check(uncheckedurl)
            url.Output = result
            url.save()
            if result == "Malicious":
                return render(request, 'malicious.html', {'result':result,'uncheckedurl':uncheckedurl,'Name':Name})
            else:
                return render(request, 'nonmalicious.html', {'result':result,'uncheckedurl':uncheckedurl,'Name':Name})

        else:
            return render(request, 'error404.html',{'uncheckedurl':uncheckedurl,'Name':Name})
    except:
	    return render(request, 'error404.html',{'uncheckedurl':uncheckedurl,'Name':Name})