#from pyexpat import features
import streamlit as st
import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
import re
from PIL import Image
from urllib.parse import urlparse
from tld import get_tld
import os.path

def show_RF():

    st.write(""" 
        # Klasifikasi Malicious URL berbasis Machine Learning 
        Aplikasi berbasis web untuk mengklasifikasi type Malicious URL (Random Forest)
        """)

    url = st.text_input("Masukkan URL: ")

    #Use of IP or not in domain
    def having_ip_address(url):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
            '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
            '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
        if match:
            # print match.group()
            return 1
        else:
            # print 'No matching pattern found'
            return 0
                        
    def abnormal_url(url):
        hostname = urlparse(url).hostname
        hostname = str(hostname)
        match = re.search(hostname, url)
        if match:
            # print match.group()
            return 1
        else:
            # print 'No matching pattern found'
            return 0

    def no_of_dir(url):
        urldir = urlparse(url).path
        return urldir.count('/')

    def no_of_embed(url):
        urldir = urlparse(url).path
        return urldir.count('//')

    def shortening_service(url):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                        'tr\.im|link\.zip\.net', url)
        if match:
            return 1
        else:
            return 0

    def suspicious_words(url):
        match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr', url)
        if match:
            return 1
        else:
            return 0

    #First Directory Length
    def fd_length(url):
        urlpath= urlparse(url).path
        try:
            return len(urlpath.split('/')[1])
        except:
            return 0

    def tldx(url):
        tld1 = get_tld(url, fail_silently=True)
        return tld1

    tld2 = tldx(url)

    #Length of Top Level Domain
    def tld_length(tld2):
        try:
            return len(tld2)
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

    if (url == ""):
        st.write("Masukkan URL yang Valid")
    else:
        def input_user_fitur ():

            data = {'use_of_ip': having_ip_address(url),
                    'abnormal_url': abnormal_url(url),
                    'count.': url.count('.'),
                    'count-www': url.count('www'),
                    'count@': url.count('@'),
                    'count_dir': no_of_dir(url),
                    'count_embed_domian': no_of_embed(url),
                    'short_url': shortening_service(url),
                    'count-https': url.count('https'),
                    'count-http': url.count('http'),
                    'count%': url.count('%'),
                    'count?': url.count('?'),
                    'count-': url.count('-'),
                    'count=': url.count('='),
                    'url_length': len(url),
                    'hostname_length': len(urlparse(url).netloc),
                    'sus_url': suspicious_words(url),
                    'fd_length': fd_length(url),
                    'tld_length': tld_length(tld2),
                    'count-digits': digit_count(url),
                    'count-letters': letter_count(url)}
                
            fitur = pd.DataFrame(data, index=[0])
            return fitur
                    

        input_df = input_user_fitur()

        # Combines user input features with entire malware dataset
        # This will be useful for the encoding phase

        malware_raw = pd.read_csv('features_ros.csv')
        malware = malware_raw.drop("Unnamed: 0",axis=1)
        df = pd.concat([input_df,malware],axis=0)

        df = df[:1] # Selects only the first row (the user input data)

        #df = df.loc[:, ~df.columns.str.contains('^Unnamed')]

        # Displays the user input features
        st.subheader('User Input features')

        if (url == ""):
            st.write('Menunggu Url di Inputkan).')
            st.write(df)
        else:
            st.write(df)

        # Reads in saved classification model
        load_model = pickle.load(open('modelRF.pkl', 'rb'))

        # Apply model to make predictions
        prediction = load_model.predict(df)
        prediction_proba = load_model.predict_proba(df)


        st.subheader('Hasil Deteksi')
        #penguins_species = np.array(['Benign','Defacement','Malware','Phising'])
        #st.write(penguins_species[prediction])
        if (prediction == 0):
            st.write('Benign')
            image = Image.open('safe.png')
            st.sidebar.image(image)
        elif(prediction == 1):
            st.write('Malware')
            image = Image.open('danger.jpeg')
            st.sidebar.image(image)
        else:
            st.write('Benign')
            image = Image.open('safe.png')
            st.sidebar.image(image)

        st.subheader('Probabilitas Deteksi')
        st.write(prediction_proba)

        st.write('Keterangan:')
        st.write('0: Benign:')
        st.write('1: Malware')