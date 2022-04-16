package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"

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

	flag.StringVar(&mode, "mode", "", "Modo de ejecución\n\tAS: Obtener ASN y Rangos IP")
	flag.StringVar(&target, "target", "", "Target a escanear")
	flag.IntVar(&threads, "t", 1, "Número de hilos")

	flag.Parse()

	if len(mode) == 0 || len(target) == 0 {
		color.Yellow("[!] Uso: main.go --mode <mode> --target <taget>\n\n")
		flag.PrintDefaults()
		return
	}

	switch mode {
	case "SA":
		ASNscan(target, threads)
	default:
		color.Red("[X] Modo de ejecución no válido")
	}

}

func ASNscan(target string, threads int) {

	// Creo la url para la API BGPView
	url := "https://api.bgpview.io/search?query_term=" + target

	// Creo el objeto del JSON

	type dataASN struct {
		Data struct {
			Asns []struct {
				Asn         int    `json:"asn"`
				Name        string `json:"name"`
				Description string `json:"description"`
				CountryCode string `json:"country_code"`
			} `json:"asns"`
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

	worker <- result
}

func banner() {
	fmt.Print("\n")
	color.Magenta("  ▄████  ▒█████    ██████  ▄████▄   ▄▄▄       ███▄    █ ")
	color.Magenta(" ██▒ ▀█▒▒██▒  ██▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ ")
	color.Magenta("▒██░▄▄▄░▒██░  ██▒░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒")
	color.Magenta("░▓█  ██▓▒██   ██░  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒")
	color.Magenta("░▒▓███▀▒░ ████▓▒░▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░")
	color.Magenta(" ░▒   ▒ ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ")
	color.Magenta("  ░   ░   ░ ▒ ▒░ ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░")
	color.Magenta("░ ░   ░ ░ ░ ░ ▒  ░  ░  ░  ░          ░   ▒      ░   ░ ░ ")
	color.Magenta("      ░     ░ ░        ░  ░ ░            ░  ░         ░ ")
	color.Magenta("                          ░                             ")

}
