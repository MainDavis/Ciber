import requests
import sys
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse, urljoin


s = requests.Session()
# Creo el User-Agent que voy a usar
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
    #Compruebo que se ha metido el http o https para que no de errores

    if ("http://" in url) or ("https://" in url):
        return True
    else:
        return False

def vulnerable(response):
    #Verifico y si el html tiene uno de los errores
    errorsMySQL = { "warning: mysql", "you have an error in your sql syntax" }

    for error in errorsMySQL:
        
        if error in response:
            return True

    return False


def scanGETSQLI(url):
    #Funcion para poner a prueba el metodo GET poniendo comillas en cada parametro y probando
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

    print(bcolors.WARNING + "\n[!] Probando SQLI por POST")
    
    forms = getFormsURL(url)
    
    if len(forms) > 0:

        print(bcolors.OKGREEN + "\n\t[+] Encontrados", len(forms), "formularios en la pagina.")
        
        for form in forms:

            info_form = getInfoForm(form)

            for c in "\"'":
                
                #Datos que vamos a enviar
                datos = {}

                for input_tag in info_form['inputs']:
                    
                    #Si el input esta oculto o tiene valor
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        try:
                            datos[input_tag["name"]] = input_tag["value"] + c
                        except:
                            pass
                    
                    #A todos los demas se añade algo con comillas
                    elif input_tag["type"] != "submit":
                        datos[input_tag["name"]] = "var" + c
                
                url = urljoin(url, info_form["action"])
            
                res = ""
                
                if info_form["action"] == "post":
                    res = s.post(url, data=datos)
                elif info_form["action"] == "get":
                    res = s.get(url, params=datos)
                
                if vulnerable(res):
                    print(bcolors.OKGREEN + "\n\t[+] Vulnerabilidad detectada")
                else:
                    print(bcolors.FAIL + "\n\t[-] No vulnerable")


    else:

        print(bcolors.FAIL + "\n\t[-] No se han encontrado formularios en la pagina.")


def getFormsURL(url):
    #Busca y recopila todos los forms
    print(bcolors.WARNING + "\n\t[!] Buscando formularios.")
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def getInfoForm(form):
    #Analiza el form introducido para sacar la informacion

    #Form action

    try:
        action = form.attrs.get("action").lower()
    except:
        action = None

    #Form method

    method = form.attrs.get("method", "get").lower()

    #Informacion de los inputs

    inputs = []

    for input_tag in form.find_all("input"):

        input_name = input_tag.attrs.get("name")
        input_type = input_tag.attrs.get("type","text")
        input_value = input_tag.attrs.get("value", "")

        inputs.append({"name":input_name, "type":input_type, "value":input_value})

    info = {

            "action":action,
            "method":method,
            "inputs":inputs
    }

    return info



if __name__ == "__main__":
    
    url = sys.argv[1]

    if comprobarURL(url):
    
        banner()

        print(bcolors.WARNING + "[!] Utilizando la url: " + url + "\n")
    
        scanGETSQLI(url)

        scanPOSTSQLI(url)

    else:

        print(bcolors.FAIL + "\n[-] No has introducido bien la url, añade http:// o https://")
