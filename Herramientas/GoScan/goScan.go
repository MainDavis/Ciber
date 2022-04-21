package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
)

func main() {

	banner()

	// Declarar variables
	var (
		mode    string
		target  string
		threads int
	)

	flag.StringVar(&mode, "mode", "", "Modo de ejecución\n\tSA: Obtener ASN y Rangos IP\n\tSO: Utiliza la API Sonar para sacar dominios y subdominios (Requiere ip_ranges.csv)\n\tRE: Utiliza REverse DNS para sacar dominios y subdominios")
	flag.StringVar(&target, "target", "", "Target a escanear")
	flag.IntVar(&threads, "t", 1, "Número de hilos")

	flag.Parse()

	if len(mode) == 0 {
		color.Red("[!] Uso: main.go --mode <mode> --target <taget>\n\n")
		flag.PrintDefaults()
		return
	}

	switch mode {
	case "SA":
		if len(target) == 0 {
			color.Red("[!] Uso: main.go --mode <mode> --target <taget>\n\n")
			flag.PrintDefaults()
			return
		}
		if _, err := os.Stat(target + "/ip_ranges.csv"); err != nil {
			crearArchivosSA(target)
		}
		ASNscan(target, threads)
	case "SO":
		if len(target) == 0 {
			color.Red("[!] Uso: main.go --mode <mode> --target <taget>\n\n")
			flag.PrintDefaults()
			return
		}
		if _, err := os.Stat("mercadona/domnios.csv"); err != nil {
			crearArchivosDom(target)
		}
		obtenerDominios(target, threads)
	case "RE":
		if len(target) == 0 {
			color.Red("[!] Uso: main.go --mode <mode> --target <taget>\n\n")
			flag.PrintDefaults()
			return
		}
		if _, err := os.Stat("mercadona/dominios.csv"); err != nil {
			crearArchivosDom(target)
		}
		reverseDNS(target, threads)
	case "prueba":
		prueba(target)
	default:
		color.Red("[X] Modo de ejecución no válido")
	}

}

func crearArchivosDom(target string) {

	// Creo la carpeta de resultados con el nombre de la empresa si no existe

	if _, err := os.Stat(target); os.IsNotExist(err) {

		err := os.Mkdir(target, 0755)

		if err != nil {
			color.Red("Error al crear la carpeta de resultados")
			return
		}

	}

	// Crear archivo de dominios.csv

	file, err := os.Create(target + "/dominios.csv")

	if err != nil {
		color.Red("[-] Error al crear archivo dominios.csv")
		color.Red(err.Error())
	}

	defer file.Close()

	// Escribo las cabeceras

	file.WriteString("Dominio,IP,Número de subdominios\n")

	// Crear archivo de subdominios.csv

	file2, err := os.Create(target + "/subdominios.csv")

	if err != nil {
		color.Red("[-] Error al crear archivo subdominios.csv")
		color.Red(err.Error())
	}

	defer file2.Close()

	// Escribo las cabeceras

	file2.WriteString("Subdominio,Dominio,IP\n")

}

func crearArchivosSA(target string) {

	// Creo la carpeta de resultados con el nombre de la empresa si no existe

	if _, err := os.Stat(target); os.IsNotExist(err) {

		err := os.Mkdir(target, 0755)

		if err != nil {
			color.Red("Error al crear la carpeta de resultados")
			return
		}

	}

	// Crear archivo de asn.csv

	file, err := os.Create(target + "/asn.csv")

	if err != nil {
		color.Red("[-] Error al crear archivo asn.csv")
		color.Green(err.Error())
	}

	defer file.Close()

	// Escribo las cabeceras

	file.WriteString("ASN,Organización,Descripción,País\n")

	// Crear archivo de ip_ranges.csv

	file2, err := os.Create(target + "/ip_ranges.csv")

	if err != nil {
		color.Red("[-] Error al crear archivo ip_ranges.csv")
		color.Green(err.Error())
	}

	defer file2.Close()

	// Escribo las cabeceras

	file2.WriteString("Rango,ASN,Organización,Descripción,País,Rango padre\n")

}

func reverseDNS(target string, threads int) {

	color.Yellow("[!] Obteniendo dominios y subdominios de " + target + " ...\n\n")

	url := "https://sonar.omnisint.io/tlds/" + strings.ToLower(target)

	// Llamo a la API

	resp, err := http.Get(url)

	if err != nil {
		color.Red("Error al llamar a la API")
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		color.Red("Error al leer el body")
		return
	}

	// Creo un array con los resultados
	var dominios []string

	err = json.Unmarshal(body, &dominios)

	if err != nil {
		color.Red("Error al leer el JSON")
		return
	}

	color.Green("[+] Obtenidos " + strconv.Itoa(len(dominios)) + " dominios\n\n")
	color.Yellow("[!] Escaneando dominios ...\n\n")

	// Preparo la barra de progreso

	bar := pb.StartNew(len(dominios))

	// Preparo el archivo dominios.csv

	fileDom, err := os.OpenFile(target+"/dominios.csv", os.O_APPEND|os.O_WRONLY, 0600)

	if err != nil {
		color.Red("Error al crear el archivo dominios.csv")
		return
	}

	defer fileDom.Close()

	writerDom := csv.NewWriter(fileDom)

	// Preparo el archivo subdominios.csv

	fileSub, err := os.OpenFile(target+"/subdominios.csv", os.O_APPEND|os.O_WRONLY, 0600)

	if err != nil {
		color.Red("Error al crear el archivo subdominios.csv")
		return
	}

	defer fileSub.Close()

	writerSub := csv.NewWriter(fileSub)

	// Escaneo los dominios

	var wg sync.WaitGroup

	workerDom := make(chan map[string][]string, threads)
	workerSub := make(chan map[string][]string, threads)

	for _, subdominio := range dominios {
		wg.Add(1)
		go analizarDominio(subdominio, &wg, workerDom, workerSub, bar)
	}

	for i := 0; i < len(dominios); i++ {

		dominios := <-workerDom
		subdominios := <-workerSub

		for key, value := range dominios {
			writerDom.Write([]string{key, value[0], value[1]})
		}

		for key, value := range subdominios {
			writerSub.Write([]string{key, value[0], value[1]})
		}

	}

	wg.Wait()

	bar.Finish()

	writerDom.Flush()
	writerSub.Flush()

	color.Green("\n[+] Escaneo finalizado\n\n")

	color.Green("[+] Archivo dominios.csv y subdominios.csv generados\n\n")

}

func analizarDominio(dominio string, wg *sync.WaitGroup, chan_dominios chan map[string][]string, chan_subdominios chan map[string][]string, bar *pb.ProgressBar) {

	defer wg.Done()
	defer bar.Increment()

	ip, err := net.LookupIP(dominio)

	if err != nil {
		chan_dominios <- map[string][]string{}
		chan_subdominios <- map[string][]string{}
		return
	}

	// Obtengo el número de subdominios

	url := "https://sonar.omnisint.io/subdomains/" + strings.ToLower(dominio)

	resp, err := http.Get(url)

	if err != nil {
		chan_dominios <- map[string][]string{}
		chan_subdominios <- map[string][]string{}
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		chan_dominios <- map[string][]string{}
		chan_subdominios <- map[string][]string{}
		return
	}

	var subdominiosList []string

	err = json.Unmarshal(body, &subdominiosList)

	if err != nil {
		chan_dominios <- map[string][]string{}
		chan_subdominios <- map[string][]string{}
		return
	}

	dominios := make(map[string][]string)

	dominios[dominio] = []string{ip[0].String(), strconv.Itoa(len(subdominiosList))}

	subdominios := make(map[string][]string)

	for _, subdominio := range subdominiosList {
		ipSub, err := net.LookupIP(subdominio)

		if err != nil {
			continue
		}

		subdominios[subdominio] = []string{dominio, ipSub[0].String()}
	}

	chan_dominios <- dominios
	chan_subdominios <- subdominios

}

func ASNscan(target string, threads int) {

	bgpAPI(target, threads)

	whoisXMLAPI(target, threads)

	color.Yellow("\n[+] Escaneo completado\n\n")

	//Quito duplicados en asn.csv e ip_ranges.csv

	color.Yellow("[!] Eliminando duplicados en asn.csv e ip_ranges.csv ...\n")

	quitarDuplicados(target)
}

func quitarDuplicados(target string) {

	// Quito las filas que tienen el mismo Rango en asn.csv

	fileASN, err := os.OpenFile(target+"/asn.csv", os.O_APPEND, 0777)

	if err != nil {
		color.Red("[X] Error al abrir asn.csv")
		return
	}

	defer fileASN.Close()

	readerASN := csv.NewReader(fileASN)

	readerASN.Comma = ','

	readerASN.FieldsPerRecord = -1

	recordsASN, err := readerASN.ReadAll()

	if err != nil {

		color.Red("[X] Error al leer asn.csv")
		color.Green(err.Error())
		return
	}

	var resultASN [][]string

	for _, record := range recordsASN {

		var duplicado bool

		for index, record2 := range resultASN {

			if record[0] == record2[0] {
				duplicado = true
			}

			//Añado la información que tiene la fila duplicada que no está en la primera

			for i := 1; i <= 3; i++ {
				if record2[i] == "" && record[i] != "" {
					resultASN[index][i] = record[i]
				}

			}
		}

		if !duplicado {
			resultASN = append(resultASN, record)
		}

	}

	// Reescribo el archivo asn.csv

	fileASN, err = os.Create(target + "/asn.csv")

	if err != nil {
		color.Red("[X] Error al recrear asn.csv")
		return
	}

	defer fileASN.Close()

	writerASN := csv.NewWriter(fileASN)

	writerASN.Comma = ','

	writerASN.WriteAll(resultASN)

	writerASN.Flush()

	// Quito las filas que tienen el mismo Rango en ip_ranges.csv

	fileIPRanges, err := os.OpenFile(target+"/ip_ranges.csv", os.O_APPEND|os.O_RDWR, 0600)

	if err != nil {
		color.Red("[X] Error al abrir ip_ranges.csv")
		return
	}

	defer fileIPRanges.Close()

	readerIPRanges := csv.NewReader(fileIPRanges)
	readerIPRanges.Comma = ','
	readerIPRanges.FieldsPerRecord = -1
	recordsIPRanges, err := readerIPRanges.ReadAll()

	if err != nil {

		color.Red("[X] Error al leer ip_ranges.csv")
		return
	}

	var resultIPRanges [][]string

	for _, record := range recordsIPRanges {

		var duplicado bool

		for index, record2 := range resultIPRanges {

			if record[0] == record2[0] {
				duplicado = true

				//Añado la información que tiene la fila duplicada que no está en la primera

				for i := 1; i <= 5; i++ {

					if record2[i] == "" && record[i] != "" {
						resultIPRanges[index][i] = record[i]
					}

				}

			}
		}

		if !duplicado {
			resultIPRanges = append(resultIPRanges, record)
		}

	}

	// Reescribo el archivo ip_ranges.csv

	fileIPRanges, err = os.Create(target + "/ip_ranges.csv")

	if err != nil {
		color.Red("[X] Error al recrear ip_ranges.csv")
		return
	}

	defer fileIPRanges.Close()

	writerIPRanges := csv.NewWriter(fileIPRanges)

	writerIPRanges.Comma = ','

	writerIPRanges.WriteAll(resultIPRanges)

	writerIPRanges.Flush()

	color.Green("\n[+] Eliminación completada")

	color.Yellow("\n[+] Escaneo completado\n\n")

}

func whoisXMLAPI(target string, threads int) {

	// Creo la url para la API whoisXML
	url := "https://ip-netblocks.whoisxmlapi.com/api/v2?apiKey=at_U77VgbyyPxlH5xAKgFM37j4l6wy8N&org[]=" + target

	color.Yellow("\n[!] Utilizando la API whoisXMLAPI\n\n")

	// Creo el objeto del JSON

	type dataASN struct {
		Result struct {
			Inetnums []struct {
				Inetnum string `json:"inetnum"`
				As      struct {
					Asn  int    `json:"asn"`
					Name string `json:"name"`
				} `json:"as"`
				Description []string `json:"description"`
				Country     string   `json:"country"`
				Org         struct {
					Name string `json:"name"`
				} `json:"org"`
			} `json:"inetnums"`
		} `json:"result"`
	}

	color.Yellow("[!] Llamando a la API:" + url + "\n\n")

	resp, err := http.Get(url)

	if err != nil {
		color.Red("[-] Error al llamar a la API")
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		color.Red("[-] Error al leer el body")
		return
	}

	var data dataASN

	if err := json.Unmarshal(body, &data); err != nil {
		color.Red("[-] Error al leer el JSON")
		return
	}

	color.Green("[+] Datos obtenidos con exito, escribiendo datos del ASN en asn.csv ...\n\n")

	// Abro asn.csv e ip_ranges.csv

	fileASN, err := os.OpenFile(target+"/asn.csv", os.O_APPEND|os.O_WRONLY, 0600)

	if err != nil {
		color.Red("[-] Error al abrir el archivo")
		return
	}

	defer fileASN.Close()

	fileCSV, err := os.OpenFile(target+"/ip_ranges.csv", os.O_APPEND|os.O_WRONLY, 0600)

	if err != nil {
		color.Red("[-] Error al abrir el archivo")
		return
	}

	defer fileCSV.Close()

	writerASN := csv.NewWriter(fileASN)
	writerCSV := csv.NewWriter(fileCSV)

	for _, asn := range data.Result.Inetnums {

		description := ""

		if len(asn.Description) != 0 {
			description = asn.Description[0]
		}

		name := asn.As.Name

		// Si org.name no esta vacio, lo añado a name

		if len(asn.Org.Name) != 0 {
			name = name + " (" + asn.Org.Name + ")"
		}

		writerASN.Write([]string{
			fmt.Sprintf("%d", asn.As.Asn),
			name,
			description,
			asn.Country,
		})

		// Saco el rango de la IP

		ipRange := strings.Split(asn.Inetnum, "-")

		ipRange[0] = strings.TrimSpace(ipRange[0])
		ipRange[1] = strings.TrimSpace(ipRange[1])

		rango, err := iPv4RangeToCIDRRange(ipRange[0], ipRange[1])

		if err != nil {
			color.Red("[-] Error al obtener el rango de la IP")
			return
		}

		writerCSV.Write([]string{
			rango[0],
			fmt.Sprintf("%d", asn.As.Asn),
			name,
			description,
			asn.Country,
			"",
		})
	}

	writerASN.Flush()
	writerCSV.Flush()

	color.Green("[+] Datos escritos en asn.csv e ip_ranges.csv")

}

func bgpAPI(target string, threads int) {
	// Creo la url para la API BGPView
	url := "https://api.bgpview.io/search?query_term=" + target

	color.Yellow("[!] Utilizando la API BGPView\n\n")

	// Creo el objeto del JSON

	type dataASN struct {
		Data struct {
			Asns []struct {
				Asn         int    `json:"asn"`
				Name        string `json:"name"`
				Description string `json:"description"`
				CountryCode string `json:"country_code"`
			} `json:"asns"`
			Ipv4_prefixes []struct {
				Prefix       string `json:"prefix"`
				Name         string `json:"name"`
				Description  string `json:"description"`
				CountryCode  string `json:"country_code"`
				ParentPrefix string `json:"parent_prefix"`
			} `json:"ipv4_prefixes"`
			Ipv6_prefixes []struct {
				Prefix       string `json:"prefix"`
				Name         string `json:"name"`
				Description  string `json:"description"`
				CountryCode  string `json:"country_code"`
				ParentPrefix string `json:"parent_prefix"`
			} `json:"ipv6_prefixes"`
		} `json:"data"`
	}

	color.Yellow("[!] Llamando a la API: " + url + "\n\n")

	resp, err := http.Get(url)

	if err != nil {
		color.Red("[-] Error al llamar a la API")
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		color.Red("[-] Error al leer el body")
		return
	}

	var data dataASN

	if err := json.Unmarshal(body, &data); err != nil {
		color.Red("[-] Error al leer el JSON")
		return
	}

	color.Green("[+] Datos obtenidos con exito, escribiendo datos del ASN en asn.csv ...\n\n")

	// Creo el archivo CSV con los datos
	file, err := os.OpenFile(target+"/asn.csv", os.O_APPEND|os.O_WRONLY, 0600)

	if err != nil {
		color.Red("[-] Error al abrir asn.csv")
		color.Red(err.Error())
		return
	}

	defer file.Close()

	writer := csv.NewWriter(file)

	for _, asn := range data.Data.Asns {
		err := writer.Write([]string{
			fmt.Sprintf("%d", asn.Asn),
			asn.Name,
			asn.Description,
			asn.CountryCode,
		})

		if err != nil {
			color.Red("[-] Error al escribir en el archivo")
			return
		}
	}

	writer.Flush()

	color.Green("[+] Archivo creado: asn.csv\n")

	// Creo el archivo CSV con los datos
	file_ranges, err := os.OpenFile(target+"/ip_ranges.csv", os.O_APPEND|os.O_WRONLY, 0600)

	if err != nil {
		color.Red("[-] Error al abrir ip_ranges.csv")
		return
	}

	defer file_ranges.Close()

	writer = csv.NewWriter(file_ranges)
	defer writer.Flush()

	// Escibo los datos de ipv4 e ipv6

	for _, ipv4 := range data.Data.Ipv4_prefixes {
		err := writer.Write([]string{
			ipv4.Prefix,
			"",
			ipv4.Name,
			ipv4.Description,
			ipv4.CountryCode,
			ipv4.ParentPrefix,
		})

		if err != nil {
			color.Red("[-] Error al escribir en el archivo")
			return
		}
	}

	for _, ipv6 := range data.Data.Ipv6_prefixes {
		err := writer.Write([]string{
			ipv6.Prefix,
			"",
			ipv6.Name,
			ipv6.Description,
			ipv6.CountryCode,
			ipv6.ParentPrefix,
		})

		if err != nil {
			color.Red("[-] Error al escribir en el archivo")
			return
		}
	}

	// Creo el canal para los hilos

	worker := make(chan [][]string, threads)

	var wg sync.WaitGroup

	for _, asn := range data.Data.Asns {

		// Creo la url para la API BGPView
		url := "https://api.bgpview.io/asn/" + fmt.Sprintf("%d", asn.Asn) + "/prefixes"

		go Worker(url, worker, &wg)

		datos := <-worker

		for _, datos := range datos {

			err := writer.Write([]string{
				datos[0],
				fmt.Sprintf("%d", asn.Asn),
				asn.Name,
				asn.Description,
				asn.CountryCode,
				datos[1],
			})

			if err != nil {
				color.Red("[-] Error al escribir en el archivo")
				return
			}
		}

		wg.Wait()

	}

	color.Green("\n[+] Archivo creado: ip_ranges.csv")

}

func Worker(url string, worker chan [][]string, wg *sync.WaitGroup) {

	wg.Add(1)
	defer wg.Done()

	type dataIpRanges struct {
		Data struct {
			Ipv4_prefixes []struct {
				Prefix string `json:"prefix"`
				Parent struct {
					Prefix string `json:"prefix"`
				} `json:"parent"`
			} `json:"ipv4_prefixes"`
			Ipv6_prefixes []struct {
				Prefix string `json:"prefix"`
				Parent struct {
					Prefix string `json:"prefix"`
				} `json:"parent"`
			} `json:"ipv6_prefixes"`
		} `json:"data"`
	}

	color.Yellow("[!] Llamando a la API: " + url)

	resp, err := http.Get(url)

	if err != nil {
		color.Red("Error al llamar a la API")
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		color.Red("Error al leer el body")
		return
	}

	var data dataIpRanges

	if err := json.Unmarshal(body, &data); err != nil {
		color.Red("Error al leer el JSON")
		return
	}

	var result [][]string

	for _, ip := range data.Data.Ipv4_prefixes {
		result = append(result, []string{
			ip.Prefix,
			ip.Parent.Prefix,
		})
	}

	for _, ip := range data.Data.Ipv6_prefixes {
		result = append(result, []string{
			ip.Prefix,
			ip.Parent.Prefix,
		})
	}

	worker <- result
}

func obtenerDominios(target string, threads int) {

	color.Yellow("\n[!] Obteniendo dominios de los rangos Ipv4\n\n")

	// Leo ip_ranges.csv y recogo todos los rangos ipv4
	file, err := os.Open(target + "/ip_ranges.csv")

	if err != nil {
		color.Red("[-] Error al abrir el archivo")
		return
	}

	defer file.Close()

	reader := csv.NewReader(file)

	var rangos []string

	for {
		record, err := reader.Read()

		if err == io.EOF {
			break
		}

		if err != nil {
			color.Red("[-] Error al leer el archivo")
			color.Green(err.Error())
			return
		}

		if record[0] == "Rango" {
			continue
		}

		rangos = append(rangos, record[0])
	}

	// Preparo el archivo dominos.csv

	file_dom, err := os.OpenFile(target+"/dominios.csv", os.O_APPEND|os.O_WRONLY, 0600)

	if err != nil {
		color.Red("[-] Error al abrir el archivo dominios.csv")
		color.Green(err.Error())
		return
	}

	defer file_dom.Close()

	writer := csv.NewWriter(file_dom)

	defer writer.Flush()

	// Preparo el archivo subdominos.csv

	file_sub, err := os.OpenFile(target+"/subdominios.csv", os.O_APPEND|os.O_WRONLY, 0600)

	if err != nil {
		color.Red("[-] Error al abrir el archivo subdominios.csv")
		return
	}

	defer file_sub.Close()

	writerSubdominios := csv.NewWriter(file_sub)

	defer writerSubdominios.Flush()

	// Creo el canal para los hilos

	chan_rangos := make(chan string, threads)
	chan_dominios := make(chan [][]string, threads)

	var wg sync.WaitGroup

	bar := pb.StartNew(len(rangos))

	for i := 0; i < len(rangos); i++ {
		go getDominio(chan_rangos, chan_dominios, &wg, bar)
	}

	for _, rango := range rangos {
		wg.Add(1)
		chan_rangos <- rango
	}

	dominios := make(map[string][]string)
	ips := make(map[string][]string)

	for i := 0; i < len(rangos); i++ {

		datos := <-chan_dominios

		for _, datos := range datos {

			// Saco los dominios de las url
			dominioSplit := strings.Split(datos[0], ".")

			dominio := dominioSplit[len(dominioSplit)-2] + "." + dominioSplit[len(dominioSplit)-1]

			dominios[dominio] = append(dominios[dominio], datos[0])

			ips[dominio] = append(ips[dominio], datos[1])

			if err != nil {
				color.Red("[-] Error al escribir en el archivo")
				return
			}

		}
	}

	// Escribo el archivo dominios.csv

	for dominio, subdominio := range dominios {

		writer.Write([]string{
			dominio,
			ips[dominio][0],
			strconv.Itoa(len(subdominio)),
		})

	}

	// Escribo el archivo subdominios.csv

	for dominio, subdominio := range dominios {

		for i, subdominio := range subdominio {

			writerSubdominios.Write([]string{
				subdominio,
				dominio,
				ips[dominio][i],
			})

		}

	}

	wg.Wait()

	bar.Finish()

	close(chan_rangos)
	close(chan_dominios)

	color.Green("\n[+] Archivos creados: dominios.csv, subdominios.csv\n\n")

}

func getDominio(chan_rangos chan string, chan_dominios chan [][]string, wg *sync.WaitGroup, bar *pb.ProgressBar) {

	// Creo la url para la API Sonar
	url := "https://sonar.omnisint.io/reverse/" + <-chan_rangos

	resp, err := http.Get(url)

	if err != nil {
		color.Red("Error al llamar a la API")
		wg.Done()
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if string(body) == "{\"error\":\"no results found\"}" || string(body) == "{\"error\":\"IPv6 is not supproted\"}" || string(body) == "404 page not found" {
		chan_dominios <- [][]string{}
		bar.Increment()
		wg.Done()
		return
	}

	if err != nil {
		color.Red("Error al leer el body")
		wg.Done()
		return
	}

	json_map := map[string][]string{}

	if err := json.Unmarshal(body, &json_map); err != nil {
		color.Red("Error al leer el JSON")
		color.Red(string(body))
		wg.Done()
		return
	}

	// Creo una lista de dominios

	var dominios [][]string

	for key, value := range json_map {

		for _, dominio := range value {
			dominios = append(dominios, []string{
				dominio,
				key,
			})
		}
	}

	bar.Increment()

	chan_dominios <- dominios

	wg.Done()

}

func banner() {
	fmt.Print("\n")

	color.Red("  ▄████  ▒█████    ██████  ▄████▄   ▄▄▄       ███▄    █ ")
	color.Red(" ██▒ ▀█▒▒██▒  ██▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ ")
	color.Red("▒██░▄▄▄░▒██░  ██▒░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒")
	color.Red("░▓█  ██▓▒██   ██░  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒")
	color.Red("░▒▓███▀▒░ ████▓▒░▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░")
	color.Red(" ░▒   ▒ ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ")
	color.Red("  ░   ░   ░ ▒ ▒░ ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░")
	color.Red("░ ░   ░ ░ ░ ░ ▒  ░  ░  ░  ░          ░   ▒      ░   ░ ░ ")
	color.Red("      ░     ░ ░        ░  ░ ░            ░  ░         ░ ")
	color.Red("                          ░                             ")

}

func iPv4RangeToCIDRRange(ipStart string, ipEnd string) (cidrs []string, err error) {

	cidr2mask := []uint32{
		0x00000000, 0x80000000, 0xC0000000,
		0xE0000000, 0xF0000000, 0xF8000000,
		0xFC000000, 0xFE000000, 0xFF000000,
		0xFF800000, 0xFFC00000, 0xFFE00000,
		0xFFF00000, 0xFFF80000, 0xFFFC0000,
		0xFFFE0000, 0xFFFF0000, 0xFFFF8000,
		0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
		0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00,
		0xFFFFFF00, 0xFFFFFF80, 0xFFFFFFC0,
		0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFF8,
		0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF,
	}

	ipStartUint32 := iPv4ToUint32(ipStart)
	ipEndUint32 := iPv4ToUint32(ipEnd)

	if ipStartUint32 > ipEndUint32 {
		log.Fatalf("start IP:%s must be less than end IP:%s", ipStart, ipEnd)
	}

	for ipEndUint32 >= ipStartUint32 {
		maxSize := 32
		for maxSize > 0 {

			maskedBase := ipStartUint32 & cidr2mask[maxSize-1]

			if maskedBase != ipStartUint32 {
				break
			}
			maxSize--

		}

		x := math.Log(float64(ipEndUint32-ipStartUint32+1)) / math.Log(2)
		maxDiff := 32 - int(math.Floor(x))
		if maxSize < maxDiff {
			maxSize = maxDiff
		}

		cidrs = append(cidrs, uInt32ToIPv4(ipStartUint32)+"/"+strconv.Itoa(maxSize))

		ipStartUint32 += uint32(math.Exp2(float64(32 - maxSize)))
	}

	return cidrs, err
}

//Convert IPv4 to uint32
func iPv4ToUint32(iPv4 string) uint32 {

	ipOctets := [4]uint64{}

	for i, v := range strings.SplitN(iPv4, ".", 4) {
		ipOctets[i], _ = strconv.ParseUint(v, 10, 32)
	}

	result := (ipOctets[0] << 24) | (ipOctets[1] << 16) | (ipOctets[2] << 8) | ipOctets[3]

	return uint32(result)
}

//Convert uint32 to IP
func uInt32ToIPv4(iPuInt32 uint32) (iP string) {
	iP = fmt.Sprintf("%d.%d.%d.%d",
		iPuInt32>>24,
		(iPuInt32&0x00FFFFFF)>>16,
		(iPuInt32&0x0000FFFF)>>8,
		iPuInt32&0x000000FF)
	return iP
}
