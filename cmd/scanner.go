package cmd

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/brotherpowers/ipsubnet"
	"github.com/gookit/color"
	"github.com/valyala/fasthttp"
)

var vulnerableIps []string

func init() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		writeLines(vulnerableIps, "./output.txt")
		os.Exit(1)
	}()
}

func (scan *Scanner) Scan() {
	color.Info.Prompt("Creating IP's")
	tmp, err := Hosts(scan.IP)
	if err != nil {
		log.Fatal(err)
	}
	color.Info.Prompt("Scanner Start")
	start := time.Now()
	countOfIPs := len(tmp)
	countOfIPsBlocks := int(math.Ceil(float64(countOfIPs) / float64(scan.thread)))
	var wg sync.WaitGroup
	wg.Add(scan.thread)
	for i, k, j := 0, 0, 0; i < scan.thread; i++ {
		if i < scan.thread {
			j += countOfIPsBlocks
			if j > countOfIPs {
				j = k + (countOfIPs - k)
			}
		}
		IPsBlock := tmp[k:j]
		go syncGroup(&wg, i*countOfIPsBlocks, IPsBlock, scan)
		time.Sleep(time.Second)
		k += countOfIPsBlocks
		if j == countOfIPs {
			break
		}
	}
	wg.Wait()
	writeLines(vulnerableIps, "./output.txt")
	elapsedTime := time.Since(start)
	fmt.Println()
	color.Info.Prompt("Total Time For Execution: %s", elapsedTime.String())

}

func makeRequest(ip string, path string, port string, RTime int, ssl bool, verbose bool) {
	protocol := ""

	if port == "443" {
		protocol = "https://"
	} else {
		protocol = "http://"
	}
	if ssl == true {
		protocol = "https://"
	}
	fullRPath := protocol + ip + ":" + port + "/" + path
	statusCodeInt, _, err := fasthttp.GetTimeout(nil, fullRPath, time.Duration(RTime)*time.Second)
	statusCode := strconv.Itoa(statusCodeInt)
	if err == nil {
		if verbose == true {
			appendToVulnerableIps(fullRPath + " -> " + statusCode)
		} else {
			if statusCodeInt == 200 {
				appendToVulnerableIps(fullRPath + " -> " + statusCode)
			}
		}
	}
}

func syncGroup(wg *sync.WaitGroup, rank int, tmp []string, scan *Scanner) {
	defer wg.Done()
	path := ""
	for i, _ := 0, rank; i < len(tmp); i++ {
		for j := 0; j < len(scan.Ports); j++ {
			if scan.wcdb == true {
				path = ".svn/wc.db"
				color.LightCyan.Printf("\033[2K\rScanning %s -> Number of vulnerable URLs %d", tmp[i]+":"+scan.Ports[j]+"/"+path, len(vulnerableIps))
				makeRequest(tmp[i], path, scan.Ports[j], scan.RTime, scan.ssl, scan.verbose)
			}
			if scan.entries == true {
				path = ".svn/entries"
				color.LightCyan.Printf("\033[2K\rScanning %s -> Number of vulnerable URLs %d", tmp[i]+":"+scan.Ports[j]+"/"+path, len(vulnerableIps))
				makeRequest(tmp[i], path, scan.Ports[j], scan.RTime, scan.ssl, scan.verbose)
			}
		}
	}
}

func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func Hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, nil

	default:
		return ips[1 : len(ips)-1], nil
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func appendToVulnerableIps(url string) {
	vulnerableIps = append(vulnerableIps, url)
}

func scanInfo(ip string, mask int) {
	sub := ipsubnet.SubnetCalculator(ip, mask)
	color.Info.Prompt("IP Range => %s", sub.GetIPAddressRange())
	color.Info.Prompt("Network Size => %d", sub.GetNetworkSize())
	color.Info.Prompt("%d IP's will be scan", sub.GetNumberAddressableHosts())
}
