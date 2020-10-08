import requests
from requests.auth import HTTPBasicAuth
import re
import json
import argparse
import sys
import os

VERSION = "0.2"

requests.packages.urllib3.disable_warnings()

default_credentials = [{"username": "guest", "password": "guest"},
                       {"username": "admin", "password": "admin"}]

certs = ["browser.p12"]

url_subfixes = ["alfresco/", 
                "alfresco/api/-",
                "alfresco/cmisws/cmis",
                "alfresco/cmisws/cmis?wsdl",
                "alfresco/faces/jsp/dashboards/container.jsp",
                "alfresco/page/index", 
                "alfresco/page/installer", 
                "alfresco/s/index", 
                "alfresco/webdav",
                "share/service/", 
                "alfresco/service/index", 
                "alfresco/service/installer",
                "share/page/",
                "share/page/index",
                "share/page/installer",
                "share/page/script/",
                "share/service/installer",
                "share/page/user/admin/dashboard",
                "solr4/"]

cert_url_subfixes = ["solr4/"]

form_url_subfixes = [{"name": "Dashboard",
                      "form": "share/page/dologin", 
                      "success": "/share/page/user/admin/dashboard", 
                      "failure": "/share/page/user/admin/dashboard?error=true"}]

sections = {"CMIS Web Services": ["cmis wsdl for all services", "xmlns:cmis"],
            "Dashboard": [">my alfresco<", 
                          ">mein alfresco<", 
                          ">mi alfresco<",
                          ">mon alfresco<",
                          ">il mio alfresco<",
                          ">min alfresco<",
                          ">mijn alfresco<",
                          ">o meu alfresco<",
                          ">alfresco &raquo; user dashboard<"],
            "Detailed error pages": [" error</title>", "exception report"],
            "Solr4 Dashboard": [">solr admin<"],
            "Web Scripts Home": ["web scripts home"],
            "Web Scripts Installer": ["web scripts installer"],
            "WebDav": ["directory listing for"],
            "Welcome Page": ["welcome to alfresco"]}


def get_alfresco_version_from_xml(target_url, verify):
    response = requests.get("{0}alfresco/service/api/login?u=invaliduser&pw=blablabla".format(target_url), auth=HTTPBasicAuth('guest', 'guest'), verify=verify)
    if response.status_code == 401:
        response = requests.get("{0}alfresco/service/api/login?u=invaliduser&pw=blablabla".format(target_url), verify=verify)
    version = re.search(r'<server>(.*)<\/server>', response.text, re.IGNORECASE)
    return version.group(1)


def get_alfresco_version_from_json(target_url, verify):
    response = requests.get("{0}alfresco/api/-default-/public/cmis/versions/1.1/atom".format(target_url), auth=HTTPBasicAuth('guest', 'guest'), verify=verify)
    version = json.loads(response.text)["server"]
    return version


def get_tomcat_jboss_version(target_url, verify):
    response = requests.get('{0}alfresco/webdav/asfdsad'.format(target_url), auth=HTTPBasicAuth('guest', 'guest'), verify=verify)
    if response.status_code == 401:
        response = requests.get('{0}alfresco/api/-'.format(target_url), verify=verify)
    title = re.search(r'<title>(.*)<\/title>', response.text, re.IGNORECASE)
    title = title.group(1)
    found_string = None
    if " - Error report" in title:
        found_string = title.replace(" - Error report", "").strip()
    if found_string is None:
        h3 = re.search(r'<h3>(.*)<\/h3>', response.text, re.IGNORECASE)
        h3 = h3.group(1)
        if "Tomcat" in h3:
            found_string = h3
    return found_string


def get_spring_webscripts_version(target_url, verify):
    response = requests.get('{0}share/page/script/'.format(target_url), auth=HTTPBasicAuth('guest', 'guest'), verify=verify)
    version = re.search(r'<tr><td><b>Server<\/b>:<\/td><td>(.*)<\/td>', response.text, re.IGNORECASE)
    return version.group(1)


def check_public_urls(target_url, verify):
    for url_subfix in url_subfixes:
        full_url = '{0}{1}'.format(target_url, url_subfix)
        try:
            response = requests.get(full_url, verify=verify)
        except requests.exceptions.ConnectionError as e:
            continue
        if ((response.status_code < 400) or 
            (url_subfix in ["alfresco/api/-", "share/page/script/"] and response.status_code >= 500)):
            for name, markers in sections.items():
                for marker in markers:
                    if marker in response.text.lower():
                        yield {"name": name, "url": full_url, "auth": None}
                        break
        else:
            for credentials_set in default_credentials:
                try:
                    response = requests.get(full_url, auth=HTTPBasicAuth(credentials_set["username"], credentials_set["password"]), verify=False)
                except requests.exceptions.ConnectionError as e:
                    continue
                if ((response.status_code < 400) or 
                    (url_subfix in ["alfresco/api/-", "share/page/script/"] and response.status_code >= 500)):
                    for name, markers in sections.items():
                        for marker in markers:
                            if marker in response.text.lower():
                                yield {"name": name, "url": full_url, "auth": credentials_set}
                                break


def check_certs(target_url, verify):
    from requests_pkcs12 import get
    for url_subfix in cert_url_subfixes:
        full_url = '{0}{1}'.format(target_url, url_subfix)
        for cert in certs:
            try:
                response = get(full_url, pkcs12_filename=os.path.join(sys.path[0], cert), pkcs12_password='alfresco', verify=verify)
            except requests.exceptions.ConnectionError as e:
                continue
            if response.status_code < 400:
                for name, markers in sections.items():
                    for marker in markers:
                        if marker in response.text.lower():
                            yield {"name": name, "url": full_url, "certificate": cert}
                            break



def check_forms(target_url, verify):
    for url_subfix in form_url_subfixes:
        full_url = '{0}{1}'.format(target_url, url_subfix["form"])
        success_url = '{0}{1}'.format(target_url, url_subfix["failure"][:1])
        for credentials_set in default_credentials:
            payload = {"success": url_subfix["success"], 
                       "failure": url_subfix["failure"],
                       "username": credentials_set["username"],
                       "password": credentials_set["password"]}
            try:
                response = requests.post(full_url, data=payload, verify=verify, allow_redirects=False)
            except requests.exceptions.ConnectionError as e:
                continue
            if response.status_code == 302 and "Location" in response.headers:
                if response.headers["Location"].endswith(url_subfix["success"]):
                    yield {"name": url_subfix["name"], "url": success_url, "auth": credentials_set}


def main(target_url, insecure):
    if target_url.endswith("/") is False:
        target_url = "{0}/".format(target_url)

    verify = not insecure

    print("======== ALFRESCO VERSION ========")

    try:
        alfresco_version = get_alfresco_version_from_xml(target_url, verify)
    except Exception as e:
        alfresco_version = None
    if alfresco_version is None:
        try:
            alfresco_version = get_alfresco_version_from_json(target_url, verify)
        except Exception as e:
            alfresco_version = None
    if alfresco_version is not None:
        print(alfresco_version)
        print("Check the vulnerabilities related to your Alfresco version at:")
        print("- https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&keyword=cpe%3a2.3%3aa%3aalfresco%3aalfresco")
        print("- https://www.cvedetails.com/vulnerability-list/vendor_id-13372/Alfresco.html")
    else:
        print("Can't detect Alfresco version")

    try:
        tomcat_jboss_version = get_tomcat_jboss_version(target_url, verify)
    except Exception as e:
            tomcat_jboss_version = None
    if tomcat_jboss_version is not None:
        if tomcat_jboss_version.lower().startswith("tomcat") or tomcat_jboss_version.lower().startswith("apache tomcat"):
            print("======== TOMCAT VERSION ======== ")
            print(tomcat_jboss_version)
            print("Check the vulnerabilities related to your Tomcat version at:")
            print("- https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3&keyword=cpe:2.3:a:apache:tomcat")
            print("- https://www.cvedetails.com/version-list/45/887/1/Apache-Tomcat.html")
        elif tomcat_jboss_version.lower().startswith("jboss"):
            print("======== JBOSS VERSION ======== ")
            print(tomcat_jboss_version)
        else:
            print("======== OTHER SOFTWARE VERSION ======== ")
            print(tomcat_jboss_version)
    else:
        print("Can't detect Tomcat version")

    print("======== SPRING WEBSCRIPTS VERSION ========")

    try:
        spring_webscripts_version = get_spring_webscripts_version(target_url, verify)
    except Exception as e:
            spring_webscripts_version = None
    if spring_webscripts_version is not None:
        print(spring_webscripts_version)
    else:
        print("Can't detect Spring WebScripts version")

    print("======== EXPOSED RESOURCES ========")

    found_resources = False    
    for result in check_public_urls(target_url, verify):
        found_resources = True
        if result["auth"] is None:
            if result["name"] == "Error pages":
                print("Detailed error pages are publicly available without authentication. Example: {0}".format(result["url"]))
            else:
                print("{0} is publicly available at {1} without authentication".format(result["name"], result["url"]))
        else:
            if result["name"] == "Error pages":
                print("Detailed error pages are publicly available with BasicAuth username '{0}' and password '{1}'. Example: {2} ".format(result["auth"]["username"], result["auth"]["password"], result["url"]))
            else:
                print("{0} is publicly available at {1} with BasicAuth username '{2}' and password '{3}'".format(result["name"], result["url"], result["auth"]["username"], result["auth"]["password"]))

    for result in check_forms(target_url, verify):
        found_resources = True
        print("{0} is publicly available at {1} with form username '{2}' and password '{3}'".format(result["name"], result["url"], result["auth"]["username"], result["auth"]["password"]))

    for result in check_certs(target_url, verify):
        found_resources = True
        print("{0} is publicly available at {1} with publicly available PKCS#12 certificate '{2}'. You can find the certificate in AlfrescoScan directory, with password 'alfresco'".format(result["name"], result["url"], result["certificate"]))

    if found_resources is False:
        print("Great! No publicly exposed resources were detected")
    

print(''' _______  _        _______  _______  _______  _______  _______  _______  _______  _______  _______  _       
(  ___  )( \\      (  ____ \\(  ____ )(  ____ \\(  ____ \\(  ____ \\(  ___  )(  ____ \\(  ____ \\(  ___  )( (    /|
| (   ) || (      | (    \\/| (    )|| (    \\/| (    \\/| (    \\/| (   ) || (    \\/| (    \\/| (   ) ||  \\  ( |
| (___) || |      | (__    | (____)|| (__    | (_____ | |      | |   | || (_____ | |      | (___) ||   \\ | |
|  ___  || |      |  __)   |     __)|  __)   (_____  )| |      | |   | |(_____  )| |      |  ___  || (\\ \\) |
| (   ) || |      | (      | (\\ (   | (            ) || |      | |   | |      ) || |      | (   ) || | \\   |
| )   ( || (____/\\| )      | ) \\ \\__| (____/\\/\\____) || (____/\\| (___) |/\\____) || (____/\\| )   ( || )  \\  |
|/     \\|(_______/|/       |/   \\__/(_______/\\_______)(_______/(_______)\\_______)(_______/|/     \\||/    )_) v{0}
                                                                                                             '''.format(VERSION))

parser = argparse.ArgumentParser(description="AlfrescoScan, an automated Alfresco security analyzer")
parser.add_argument("-v", "--version", help="Show program version", action="store_true")
parser.add_argument("-i", "--insecure", help="Ignore security issues with HTTPS connections", action="store_true")
parser.add_argument("-u", "--url", help="URL to scan")
args = parser.parse_args()

if args.version:
    print("AlfrescoScan v{0}".format(VERSION))

if args.url:
    print("Scanning '{0}'...".format(args.url))
    main(target_url=args.url, insecure=args.insecure)

if not args.version and not args.url:
    parser.print_help()

