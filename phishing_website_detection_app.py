import streamlit as st
import pickle
from generate_url_based_model_data import GenerateURLBasedModelData

model_path: str = "./phishing_website_detection_rf_url_based_model.pkl"

# Load from file
with open(model_path, 'rb') as file:
    model = pickle.load(file)

# set title
st.title('Detect phishing website')

# paragraph to explain what is this app about 
st.markdown('Detect phishing website using Random Forest model on URL-based features *(91% accuracy)*',True)
st.info('Better result if you input URL and not only URN (e.g. https://www.youtube.com/)')

url_to_test = st.text_input('URL to analyze', '')


if st.button("Analyze", type="primary"):
    res =  st.empty()
    info_res = st.empty()
    res.markdown('Analysis in progress..')
    info_res.markdown('*(Can take a few seconds)*')
    url_features: list = GenerateURLBasedModelData(url_to_test).extract_features()
    prediction = model.predict([url_features])[0]
    info_res.empty()
    if prediction == -1:
        res.markdown("You're URL has been identified as **legitimate** ✅")
    else:
        res.markdown("You're URL has been identified as **phishing** ❌")

# show information about features used
info_features = st.checkbox('Information about features')
if info_features:
    st.write('Twelve features are used to predict whether the URL is a phishing site or a legitimate site.')

    st.markdown('### Using the IP Address')
    st.write('If an IP address is used as an alternative of the domain name in the URL, such as “http://125.98.3.123/fake.html”, users can be sure that someone is trying to steal their personal information. Sometimes, the IP address is even transformed into hexadecimal code as shown in the following link “http://0x58.0xCC.0xCA.0x62/2/paypal.ca/index.html”.')

    st.markdown('### Long URL to Hide the Suspicious Part')
    st.write('Phishers can use long URL to hide the doubtful part in the address bar.')
    
    st.markdown('### Using URL Shortening Services “TinyURL”')
    st.write('URL shortening is a method on the “World Wide Web” in which a URL may be made considerably smaller in length and still lead to the required webpage. This is accomplished by means of an “HTTP Redirect” on a domain name that is short, which links to the webpage that has a long URL. For example, the URL “http://portal.hud.ac.uk/” can be shortened to “bit.ly/19DXSk4”.')
    
    st.markdown('### URL’s having “@” Symbol')
    st.write('Using “@” symbol in the URL leads the browser to ignore everything preceding the “@” symbol and the real address often follows the “@” symbol.')
    
    st.markdown('### Redirecting using “//”')
    st.write('The existence of “//” within the URL path means that the user will be redirected to another website.')
    
    st.markdown('### Adding Prefix or Suffix Separated by (-) to the Domain')
    st.write('The dash symbol is rarely used in legitimate URLs. Phishers tend to add prefixes or suffixes separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage. For example http://www.Confirme-paypal.com/.')
    
    st.markdown('### Sub Domain and Multi Sub Domains')
    st.write('To produce a rule for extracting this feature, we firstly have to omit the (www.) from the URL which is in fact a sub domain in itself. Then, we have to remove the (ccTLD) if it exists. Finally, we count the remaining dots. If the number of dots is greater than one, then the URL is classified as “Suspicious” since it has one sub domain. However, if the dots are greater than two, it is classified as “Phishing” since it will have multiple sub domains. Otherwise, if the URL has no sub domains, we will assign “Legitimate” to the feature.')
    
    st.markdown('### HTTPS (Hyper Text Transfer Protocol with Secure Sockets Layer)')
    st.write('The existence of HTTPS is very important in giving the impression of website legitimacy, but this is clearly not enough. The authors in (Mohammad, Thabtah and McCluskey 2012) (Mohammad, Thabtah and McCluskey 2013) suggest checking the certificate assigned with HTTPS including the extent of the trust certificate issuer, and the certificate age. Certificate Authorities that are consistently listed among the top trustworthy names include: “GeoTrust, GoDaddy, Network Solutions, Thawte, Comodo, Doster and VeriSign”. Furthermore, by testing out our datasets, we find that the minimum age of a reputable certificate is two years.')
    
    st.markdown('### Age of Domain')
    st.write('This feature can be extracted from WHOIS database (Whois 2005). Most phishing websites live for a short period of time. By reviewing our dataset, we find that the minimum age of the legitimate domain is 6 months.')
    
    st.markdown('### Favicon')
    st.write('A favicon is a graphic image (icon) associated with a specific webpage. Many existing user agents such as graphical browsers and newsreaders show favicon as a visual reminder of the website identity in the address bar. If the favicon is loaded from a domain other than that shown in the address bar, then the webpage is likely to be considered a Phishing attempt.')
    
    st.markdown('### Using Non-Standard Port')
    st.write('This feature is useful in validating if a particular service (e.g. HTTP) is up or down on a specific server. In the aim of controlling intrusions, it is much better to merely open ports that you need. Several firewalls, Proxy and Network Address Translation (NAT) servers will, by default, block all or most of the ports and only open the ones selected. If all ports are open, phishers can run almost any service they want and as a result, user information is threatened.')
    
    st.markdown('### The Existence of “HTTPS” Token in the Domain Part of the URL')
    st.write('The phishers may add the “HTTPS” token to the domain part of a URL in order to trick users. For example, http://https-www-paypal-it-webapps-mpp-home.soft-hair.com/.')
    
    st.markdown('### Source')
    st.write('README of the Phishing Website dataset by Rami Mohammad and Lee McCluskey (https://archive.ics.uci.edu/dataset/327/phishing+websites)')

# show information about features used
observation = st.checkbox('Solution observation')
if observation:
    st.write('The solution is quite slow for a real-world implementation.')
    st.write('However, the time to extract the information from the URL can be divided by using better libraries or another language.')
    st.write('Knowing that it was only for learning purpose the result is acceptable.')