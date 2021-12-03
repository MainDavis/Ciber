import requests
import sys
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse


s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

class bcolors:
    HEADER = '\033[95m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def banner():
    print("\n--------------------------------------------------------------------------------------------------------------------------------")
    print(bcolors.HEADER)
    print("  ▄████████ ████████▄    ▄█        ▄█          ▄████████  ▄████████    ▄████████ ███▄▄▄▄   ███▄▄▄▄      ▄████████    ▄████████  ")
    print("  ███    ███ ███    ███  ███       ███         ███    ███ ███    ███   ███    ███ ███▀▀▀██▄ ███▀▀▀██▄   ███    ███   ███    ███ ")
    print("  ███    █▀  ███    ███  ███       ███▌        ███    █▀  ███    █▀    ███    ███ ███   ███ ███   ███   ███    █▀    ███    ███ ")
    print("  ███        ███    ███  ███       ███▌        ███        ███          ███    ███ ███   ███ ███   ███  ▄███▄▄▄      ▄███▄▄▄▄██▀ ")
    print("▀███████████ ███    ███  ███       ███▌      ▀███████████ ███        ▀███████████ ███   ███ ███   ███ ▀▀███▀▀▀     ▀▀███▀▀▀▀▀   ")
    print("         ███ ███    ███  ███       ███                ███ ███    █▄    ███    ███ ███   ███ ███   ███   ███    █▄  ▀███████████ ")
    print("   ▄█    ███ ███  ▀ ███  ███▌    ▄ ███          ▄█    ███ ███    ███   ███    ███ ███   ███ ███   ███   ███    ███   ███    ███ ")
    print(" ▄████████▀   ▀██████▀▄█ █████▄▄██ █▀         ▄████████▀  ████████▀    ███    █▀   ▀█   █▀   ▀█   █▀    ██████████   ███    ███ ")
    print("                         ▀                                                                                           ███    ███ ")
    print(bcolors.ENDC)
    print("----------------------------------------------------- By MainDavis -------------------------------------------------------------\n\n")

def comprobarURL(url):

    if ("http://" in url) or ("https://" in url):
        return True
    else:
        return False

def vulnerable(response):

    errorsMySQL = { "warning: mysql", "you have an error in your sql syntax" }

    for error in errorsMySQL:
        
        if error in response:
            return True

    return False


def scanGETSQLI(url):
  
    print(bcolors.WARNING + "[!] Probando SQLI por GET\n")

    parse = urlparse(url)
    parameters = parse.query.split('&')
    
    if parameters[0] == "":
        print("\t" + bcolors.WARNING + "[!] No hay parametros por GET")
        return

    for parameter in parameters:
        new_url = url.replace(parameter, parameter + "'")
        res = s.get(new_url).content.decode().lower()

        new_url = url.replace(parameter, parameter + '"')
        res = res + s.get(new_url).content.decode().lower()

        if vulnerable(res):
            print("\t" + bcolors.OKGREEN + "[+] Vulnerable el parametro " + parameter.split('=')[0])
        else:
            print("\t" + bcolors.FAIL + "[-] No vulnerable el parametro " + parameter.split('=')[0])


def scanPOSTSQLI(url):

    print(bcolors.WARNING + "[!] Probando SQLI por POST")
    
    forms = getFormsURL(url)

    print(bcolors.OKGREEN + "[!] Encontrados ")
    print(len(forms))
    print(forms)

def getFormsURL(url):
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

if __name__ == "__main__":
    
    url = sys.argv[1]

    if comprobarURL(url):
    
        banner()

        print(bcolors.WARNING + "[!] Utilizando la url: " + url + "\n")
    
        scanGETSQLI(url)

        scanPOSTSQLI(url)

    else:

        print(bcolors.FAIL + "\n[-] No has introducido bien la url, añade http:// o https://")
