package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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

	flag.StringVar(&mode, "mode", "", "Modo de ejecución\n\tAS: Obtener ASN y Rangos IP\n\tRE: Hacer REverse DNS Lookup para sacar dominio y subdominios (Requiere ip_ranges.csv)")
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
		ASNscan(target, threads)
	case "RE":
		obtenerDominios(threads)
	default:
		color.Red("[X] Modo de ejecución no válido")
	}

}

func ASNscan(target string, threads int) {

	bgpAPI(target, threads)

	whoisXMLAPI(target, threads)

	color.Yellow("\n[+] Escaneo completado\n\n")

	//Quito duplicados en asn.csv e ip_ranges.csv

	color.Yellow("[!] Eliminando duplicados en asn.csv e ip_ranges.csv ...\n\n")

	quitarDuplicados()
}

func quitarDuplicados() {

	// Quito las filas que tienen el mismo Rango en asn.csv

	color.Yellow("[!] Quitando filas con el mismo ASN en asn.csv ...\n\n")

	fileASN, err := os.OpenFile("asn.csv", os.O_RDWR, 0600)

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
		return
	}

	var resultASN [][]string

	for _, record := range recordsASN {

		var duplicado bool

		for index, record2 := range resultASN {

			if record[0] == record2[0] {
				color.Yellow("[!] " + record[0] + " duplicado\n")
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

	fileASN.Truncate(0)
	fileASN.Seek(0, 0)

	writerASN := csv.NewWriter(fileASN)

	for _, record := range resultASN {
		writerASN.Write(record)
	}

	writerASN.Flush()

	// Quito las filas que tienen el mismo Rango en ip_ranges.csv

	color.Yellow("\n[!] Quitando filas con el mismo Rango en ip_ranges.csv ...\n\n")

	fileIPRanges, err := os.OpenFile("ip_ranges.csv", os.O_RDWR, 0600)

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
				color.Yellow("[!] Rango: " + record[0] + " duplicado\n")
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

	fileIPRanges.Truncate(0)
	fileIPRanges.Seek(0, 0)

	writerIPRanges := csv.NewWriter(fileIPRanges)

	for _, record := range resultIPRanges {
		writerIPRanges.Write(record)
	}

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
				As struct {
					Asn   int    `json:"asn"`
					Name  string `json:"name"`
					Route string `json:"route"`
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

	color.Green("[+] Datos obtenidos con exito, escribiendo datos del ASN en asn.csv ...")

	// Abro asn.csv e ip_ranges.csv

	fileASN, err := os.OpenFile("asn.csv", os.O_APPEND|os.O_WRONLY, 0600)

	if err != nil {
		color.Red("[-] Error al abrir el archivo")
		return
	}

	defer fileASN.Close()

	fileCSV, err := os.OpenFile("ip_ranges.csv", os.O_APPEND|os.O_WRONLY, 0600)

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

		writerCSV.Write([]string{
			asn.As.Route,
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
	file, err := os.Create("asn.csv")

	if err != nil {
		color.Red("[-] Error al crear el archivo")
		return
	}

	defer file.Close()

	writer := csv.NewWriter(file)

	// Escribo los encabezados
	writer.Write([]string{"ASN", "Organización", "Descripción", "País"})

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

	color.Green("[+] Archivo creado: asn.csv\n\n")

	// Creo el archivo CSV con los datos
	file, err = os.Create("ip_ranges.csv")

	if err != nil {
		color.Red("[-] Error al crear el archivo")
		return
	}

	defer file.Close()

	writer = csv.NewWriter(file)
	defer writer.Flush()

	// Escribo los encabezados

	writer.Write([]string{"Rango", "ASN", "Organización", "Descripción", "País", "Rango padre"})

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

func obtenerDominios(threads int) {

	color.Yellow("\n[!] Obteniendo dominios de los rangos Ipv4 e Ipv6\n\n")

	// Leo ip_ranges.csv y recogo todos los rangos ipv4 y ipv6
	file, err := os.Open("ip_ranges.csv")

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
			return
		}

		if record[0] == "Rango" {
			continue
		}

		rangos = append(rangos, record[0])
	}

	// Preparo el archivo dominos.csv

	file, err = os.Create("dominios.csv")

	if err != nil {
		color.Red("[-] Error al crear el archivo")
		return
	}

	defer file.Close()

	writer := csv.NewWriter(file)

	defer writer.Flush()

	// Preparo el archivo subdominos.csv

	file, err = os.Create("subdominios.csv")

	if err != nil {
		color.Red("[-] Error al crear el archivo")
		return
	}

	defer file.Close()

	writerSubdominios := csv.NewWriter(file)

	defer writerSubdominios.Flush()

	// Escribo los encabezados

	writer.Write([]string{"Dominio", "IP", "Numero de subdominios"})

	writerSubdominios.Write([]string{"Subdominio", "Dominio", "IP"})

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

	color.Green("\n[+] Archivos creados: dominios.csv, subdominios.csv")

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
