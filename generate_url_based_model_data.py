from urllib.parse import urlparse, ParseResult
import whois
import tldextract
import re
from datetime import datetime
import favicon
import OpenSSL
import ssl
import socket

import pandas as pd

class GenerateURLBasedModelData:
    """ Extract the features related to URL to determine if it's a phishing website
    """   
    def __init__(self, url: str) -> None:
        self.url: str = url
        self.features: ParseResult = urlparse(url)


    def using_ip_address(self) -> int:
        """ Define in an URL use an IP address as domain name

        Returns:
            bool: 1 -> Phishing feature; -1 -> Legitimate
        """
        # Detect IP address and IP address convert into hex
        ip_address_pattern: str = r"\b(?:\d{1,3}|0x[0-9A-Fa-f]{1,2})(?:\.(?:\d{1,3}|0x[0-9A-Fa-f]{1,2})){3}\b"
        return 1 if re.search(ip_address_pattern, self.url) else -1


    def is_long_url(self) -> int:
        """ Define if an URL is long or not

        Returns:
            int: 1 -> Phishing feature; 0 -> Suspicious; -1 -> Legitimate
        """
        url_len: int = len(self.url)
        if url_len < 54:
            # Legitimate
            return -1
        elif 54 <= url_len <= 75:
            # Suspicious
            return 0
        return 1


    def is_url_shortening_services_used(self) -> int:
        """ Define if an URL as been shortened

        Returns:
            int: 1 -> Phishing feature; -1 -> Legitimate
        """
        # List of the most famous shortened services
        shortened_services: list[str] = ["bit.ly", "rebrand.ly", "tinyurl.com", "zpr.io", "to.short.cm"]

        for service in shortened_services:
            if service in self.features.netloc:
                return 1
        return -1


    def have_at_symbol(self) -> int:
        """ Define if the URL use a "@" symbol 
        that leads the browser to ignore everything preceding the "@" symbol

        Returns:
            int: 1 -> Phishing feature; -1 -> Legitimate
        """
        return 1 if "@" in self.url else -1


    def use_double_slash(self) -> int:
        """ The existence of “//” within the URL path means 
        that the user will be redirected to another website.

        Returns:
            int: 1 -> Phishing feature; -1 -> Legitimate
        """
        return 1 if "//" in self.features.path else -1


    def is_dash_symbol_used(self) -> int:
        """ Determine if a dash simbol (-) is used

        Returns:
            int: 1 -> Phishing feature; -1 -> Legitimate
        """
        return 1 if "-" in self.features.netloc else -1


    def has_multiple_sub(self) -> int:
        """ Define if there are multiple sub domains

        Returns:
            int: 1 -> Phishing feature; 0 -> Suspicious; -1 -> Legitimate
        """
        subdomains = tldextract.extract(self.url).subdomain
        nb_dots: int = subdomains.count(".")
        if nb_dots == 0:
            return -1
        elif nb_dots == 1:
            return 0
        return 1


    def is_certificate_trustworthy(self) -> int:
        """ Define if a certificate for HTTPS is trustworthy.
        Trustworthy certificates: GeoTrust, GoDaddy, Network Solutions, Thawte, Comodo, Doster and VeriSign

        Returns:
            int: 1 -> Phishing feature; 0 -> Suspicious; -1 -> Legitimate
        """
        trustworthy_certificates: list = ["GeoTrust", "GoDaddy", "Network Solutions", "Thawte", "Comodo", "Doster", "VeriSign"]
        if self.features.scheme != "https":
            return 1
        try:
            certificate: str = ssl.get_server_certificate((self.features.netloc, 443))
            x509: dict = dict(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate).get_issuer().get_components())
            if x509[b"O"].decode() in trustworthy_certificates:
                return -1
            else:
                return 0
        except:
            # If certificate not possible to catch
            return 0


    def is_domain_old(self) -> int:
        """ Define if the domain is old or not

        Returns:
            int: 1 -> Phishing feature; -1 -> Legitimate
        """
        DAYS_6_MONTHS: int = 182
        try:
            if (datetime.now() - whois.whois(self.url)["creation_date"]).days >= DAYS_6_MONTHS:
                return -1
        except:
            pass
        return 1


    def is_favicon_loaded_from_a_different_domain(self) -> int:
        """ Determine if the Favicon is loaded from a different domain

        Returns:
            int: 1 -> Phishing feature; -1 -> Legitimate
        """
        try:
            domain_url_favicon: str = urlparse(favicon.get(self.url)[0].url).netloc
            if domain_url_favicon != self.features.netloc:
                return 1
        except:
            try:
                domain_url_favicon: str = favicon.get("https://" + self.url)[0].url
                if domain_url_favicon != self.features.netloc:
                    return 1
            except:
                # If we're not able to get the favicon we return Phishing 
                return 1
        return -1


    def use_non_standard_port(self) -> int:
        """ Define if non standard port are used

        Returns:
            int: 1 -> Phishing feature; -1 -> Legitimate
        """
        timeout: int = 5
        port_to_test: dict[int, int] = {21: False, 22: False, 23: False, 80: True, 
                                        443: True, 445: False, 1433: False, 
                                        1521: False, 3306: False, 3389: False}
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)  # Set a timeout for the connection attempt

        for port, v in port_to_test.items():
            try:
                result = sock.connect_ex((self.features.netloc, port))
                if result == 0:
                    if v != True:
                        return 1
                else:
                    if v != False:
                        return 1
            except socket.timeout:
                if v != False:
                    return 1
            except Exception as e:
                if v != False:
                    return 1
            finally:
                sock.close()

        return -1


    def use_https_token(self) -> int:
        """ Define if an https token is used.
        E.g. http://https-www-paypal-it-webapps-mpp-home.soft-hair.com/

        Returns:
            int: 1 -> Phishing feature; -1 -> Legitimate
        """
        return 1 if "https" in self.features.netloc else -1


    def extract_features(self) -> list[int]:
        """ Extract features from an URL 
        to determine if it's a phishing website or not using Random Forest

        Args:
            url (str): url to verify

        Returns:
            list[int]: features values
        """
        features: list = []

        features.append(self.using_ip_address())
        features.append(self.is_long_url())
        features.append(self.is_url_shortening_services_used())
        features.append(self.have_at_symbol())
        features.append(self.use_double_slash())
        features.append(self.is_dash_symbol_used())
        features.append(self.has_multiple_sub())
        features.append(self.is_certificate_trustworthy())
        features.append(self.is_domain_old())
        features.append(self.is_favicon_loaded_from_a_different_domain())
        features.append(self.use_non_standard_port())
        features.append(self.use_https_token())

        return features


if __name__ == "__main__":
    generate_url_based_model_data: GenerateURLBasedModelData = GenerateURLBasedModelData("https://www.youtube.com/")
    print(generate_url_based_model_data.using_ip_address())
    print(generate_url_based_model_data.is_long_url())
    print(generate_url_based_model_data.is_url_shortening_services_used())
    print(generate_url_based_model_data.have_at_symbol())
    print(generate_url_based_model_data.use_double_slash())
    print(generate_url_based_model_data.is_dash_symbol_used())
    print(generate_url_based_model_data.has_multiple_sub())
    print(generate_url_based_model_data.is_certificate_trustworthy())
    print(generate_url_based_model_data.is_domain_old())
    print(generate_url_based_model_data.is_favicon_loaded_from_a_different_domain())
    print(generate_url_based_model_data.use_non_standard_port())
    print(generate_url_based_model_data.use_https_token())
    res = generate_url_based_model_data.extract_features()
    print(res)
    
