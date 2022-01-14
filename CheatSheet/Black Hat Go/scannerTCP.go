package main

import (
	"fmt"
	"net"
)

func main() {
	for
	_, err := net.Dial("tcp", "scanme.nmap.org:80")
	if err == nil {
		fmt.Println("Port is open")
	} else {
		fmt.Println("Port is closed")
	}
}
