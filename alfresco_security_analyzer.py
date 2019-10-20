import requests
from requests.auth import HTTPBasicAuth
import re
import json
import argparse


default_credentials = [{"username": "guest", "password": "guest"},
                       {"username": "admin", "password": "admin"}]

url_subfixes = ["alfresco/", 
                "alfresco/faces/jsp/dashboards/container.jsp",
                "alfresco/page/index", 
                "alfresco/page/installer", 
                "alfresco/s/index", 
                "alfresco/webdav",
                "share/service/", 
                "alfresco/service/index", 
                "alfresco/service/installer",
                "share/page/index",
                "share/page/installer"
                "share/service/installer",
                "share/page/user/admin/dashboard"]

sections = {"Dashboard": [">my alfresco<", ">alfresco &raquo; user dashboard<"],
            "Web Scripts Home": ["web scripts home"],
            "Web Scripts Installer": ["web scripts installer"],
            "WebDav": ["directory listing for"],
            "Welcome Page": ["welcome to alfresco"]}


def get_alfresco_version_from_xml(target_url):
    response = requests.get("{0}alfresco/service/api/login?u=invaliduser&pw=blablabla".format(target_url), auth=HTTPBasicAuth('guest', 'guest'))
    version = re.search(r'<server>(.*)<\/server>', response.text, re.IGNORECASE)
    return version.group(1)


def get_alfresco_version_from_json(target_url):
    response = requests.get("{0}alfresco/api/-default-/public/cmis/versions/1.1/atom".format(target_url), auth=HTTPBasicAuth('guest', 'guest'))
    version = json.loads(response.text)["server"]
    return version


def get_tomcat_jboss_version(target_url):
    response = requests.get('{0}alfresco/webdav/asfdsad'.format(target_url), auth=HTTPBasicAuth('guest', 'guest'))
    title = re.search(r'<title>(.*)<\/title>', response.text, re.IGNORECASE)
    title = title.group(1)
    if " - Error report" in title:
        title = title.replace(" - Error report", "").strip()
    return title


def get_spring_webscripts_version(target_url):
    response = requests.get('{0}share/page/script/'.format(target_url), auth=HTTPBasicAuth('guest', 'guest'))
    version = re.search(r'<tr><td><b>Server<\/b>:<\/td><td>(.*)<\/td>', response.text, re.IGNORECASE)
    return version.group(1)


def check_public_urls(target_url):
    results = list()
    for url_subfix in url_subfixes:
        full_url = '{0}{1}'.format(target_url, url_subfix)
        response = requests.get(full_url)
        if response.status_code < 400:
            for name, markers in sections.items():
                for marker in markers:
                    if marker in response.text.lower():
                        yield {"name": name, "url": full_url, "auth": None}
                        break
        else:
            for credentials_set in default_credentials:
                response = requests.get(full_url, auth=HTTPBasicAuth(credentials_set["username"], credentials_set["password"]))
                if response.status_code < 400:
                    for name, markers in sections.items():
                        for marker in markers:
                            if marker in response.text.lower():
                                yield {"name": name, "url": full_url, "auth": credentials_set}
                                break

def main(target_url):
    if target_url.endswith("/") is False:
        target_url = "{0}/".format(target_url)

    print("======== ALFRESCO VERSION ========")

    try:
        alfresco_version = get_alfresco_version_from_xml(target_url)
    except Exception as e:
        alfresco_version = None
    if alfresco_version is None:
        try:
            alfresco_version = get_alfresco_version_from_json(target_url)
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
        tomcat_jboss_version = get_tomcat_jboss_version(target_url)
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
        spring_webscripts_version = get_spring_webscripts_version(target_url)
    except Exception as e:
            spring_webscripts_version = None
    if spring_webscripts_version is not None:
        print(spring_webscripts_version)
    else:
        print("Can't detect Spring WebScripts version")

    print("======== EXPOSED RESOURCES ========")

    found_resources = False    
    for result in check_public_urls(target_url):
        found_resources = True
        if result["auth"] is None:
            print("{0} is publicly available at {1} without authentication".format(result["name"], result["url"]))
        else:
            print("{0} is publicly available at {1} with username '{2}' and password '{3}'".format(result["name"], result["url"], result["auth"]["username"], result["auth"]["password"]))

    if found_resources is False:
        print("Great! No publicly exposed resources were detected")
    

print(''' _______  _        _______  _______  _______  _______  _______  _______  _______  _______  _______  _       
(  ___  )( \\      (  ____ \\(  ____ )(  ____ \\(  ____ \\(  ____ \\(  ___  )(  ____ \\(  ____ \\(  ___  )( (    /|
| (   ) || (      | (    \\/| (    )|| (    \\/| (    \\/| (    \\/| (   ) || (    \\/| (    \\/| (   ) ||  \\  ( |
| (___) || |      | (__    | (____)|| (__    | (_____ | |      | |   | || (_____ | |      | (___) ||   \\ | |
|  ___  || |      |  __)   |     __)|  __)   (_____  )| |      | |   | |(_____  )| |      |  ___  || (\\ \\) |
| (   ) || |      | (      | (\\ (   | (            ) || |      | |   | |      ) || |      | (   ) || | \\   |
| )   ( || (____/\\| )      | ) \\ \\__| (____/\\/\\____) || (____/\\| (___) |/\\____) || (____/\\| )   ( || )  \\  |
|/     \\|(_______/|/       |/   \\__/(_______/\\_______)(_______/(_______)\\_______)(_______/|/     \\||/    )_) v0.1
                                                                                                             ''')

parser = argparse.ArgumentParser(description="AlfrescoScan, an automated Alfresco security analyzer")
parser.add_argument("-v", "--version", help="show program version", action="store_true")
parser.add_argument("-u", "--url", help="url to scan")
args = parser.parse_args()

if args.version:
    print("AlfrescoScan 0.1")

if args.url:
    print("Scanning '{0}'...".format(args.url))
    main(target_url=args.url)

if not args.version and not args.url:
    parser.print_help()
