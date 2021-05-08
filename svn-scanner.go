package main

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/brotherpowers/ipsubnet"
	"github.com/docopt/docopt-go"
	"github.com/gookit/color"
	"github.com/valyala/fasthttp"
)

//Scanner Scanner
type Scanner struct {
	Ports   []string
	IP      string
	RTime   int
	wcdb    bool
	entries bool
	ssl     bool
	verbose bool
	thread  int
}

var err = false
var empyt []byte
var ips []string
var count = 0

func init() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		writeLines(ips, "output.txt")
		os.Exit(1)
	}()
}

func main() {

	usage := `
	Usage:
	svn-scanner.go --ip <ip> --ports <ports>... [--timeout <timeout> ] [--wcdb <wcdb> ] [--entries <entries> ] [--ssl <ssl>] [--verbose <verbose>] 
	svn-scanner.go -h | --help
	svn-scanner.go --version
	
	Options:
	  -h --help     Show this screen.
	  --version     Show version.
	  --ip     	IP with subnetmask.
	  --ports     	Ports to scan.
	  --timeout 	Scanner timeout for ip [default: 1000 ].
	  --wcdb 	Check .svn/wc.db [default: true].
	  --entries 	Check .svn/entries [default: false].
	  --ssl 	Check https version [default: false].
	  --verbose 	You will see all result not just http code 200 [default: false].
	  `
	scan := &Scanner{
		wcdb:    true,
		entries: false,
		ssl:     false,
		verbose: false,
		thread:  runtime.NumCPU(),
		RTime:   1000,
	}
	arguments, _ := docopt.Parse(usage, nil, true, "svn-scanner 1.0", false)
	err = scan.argumentsControl(arguments)
	if err == false {
		ips := strings.Split(scan.IP, "/")
		mask, _ := strconv.Atoi(ips[1])
		if mask > 31 {
			color.Warn.Prompt("--ip IP not valid  e.g => 127.0.0.0/24")
			return
		}
		sub := ipsubnet.SubnetCalculator(ips[0], mask)

		maxTime := time.Duration(0)
		if scan.wcdb == true && scan.entries == true {
			maxTime = time.Duration(((sub.GetNumberAddressableHosts()*len(scan.Ports)*scan.RTime)*2)/scan.thread) * time.Millisecond
		} else {
			maxTime = time.Duration((sub.GetNumberAddressableHosts()*len(scan.Ports)*scan.RTime)/scan.thread) * time.Millisecond
		}

		color.Info.Prompt("IP Range => %s", sub.GetIPAddressRange())
		color.Info.Prompt("Network Size => %d", sub.GetNetworkSize())
		color.Info.Prompt("%d IP's will be scan", sub.GetNumberAddressableHosts())
		color.Info.Prompt("Will take an average of %s", maxTime)

		Scan(scan)
	}
}

//Scan Scanner
func Scan(scan *Scanner) {
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
	for i, k, j := 0, 0, 0; i < scan.thread; i++ {
		if i < scan.thread {
			j += countOfIPsBlocks
			if j > countOfIPs {
				j = k + (countOfIPs - k)
			}
		}
		IPsBlock := tmp[k:j]
		wg.Add(1)
		go syncGroup(&wg, i*countOfIPsBlocks, IPsBlock, scan)
		time.Sleep(time.Second)
		k += countOfIPsBlocks
		if j == countOfIPs {
			break
		}
	}
	wg.Wait()
	writeLines(ips, "output.txt")
	elapsedTime := time.Since(start)
	fmt.Println()
	color.Info.Prompt("Total Time For Execution: %s", elapsedTime.String())

}

func syncGroup(wg *sync.WaitGroup, rank int, tmp []string, scan *Scanner) {
	defer wg.Done()
	path := ""
	for i, k := 0, rank; i < len(tmp); i++ {
		for j := 0; j < len(scan.Ports); j++ {
			if scan.wcdb == true {
				path = ".svn/wc.db"
				makeRequest(tmp[i], path, scan.Ports[j], scan.RTime, scan.ssl, scan.verbose)
				fmt.Printf("\rCount -> %d -> %s -> %d", k+i, tmp[i]+":"+scan.Ports[j]+"/"+path, count)
			}
			if scan.entries == true {
				path = ".svn/entries"
				makeRequest(tmp[i], path, scan.Ports[j], scan.RTime, scan.ssl, scan.verbose)
				fmt.Printf("\rCount -> %d -> %s -> %d", k+i, tmp[i]+":"+scan.Ports[j]+"/"+path, count)
			}
		}
	}
}
func makeRequest(url string, path string, port string, RTime int, ssl bool, verbose bool) {
	protocol := ""
	if ssl == true {
		protocol = "https://"
	}
	protocol = "http://"

	StatusCode, _, err := fasthttp.GetTimeout(empyt, protocol+url+":"+port+"/"+path, time.Duration(RTime)*time.Millisecond)
	if err == nil {
		if verbose == true {
			count++
			s := strconv.Itoa(StatusCode)
			ips = append(ips, url+":"+port+"/"+path+" -> "+s)
		} else {
			if StatusCode == 200 {
				count++
				s := strconv.Itoa(StatusCode)
				ips = append(ips, url+":"+port+"/"+path+" -> "+s)

			}
		}
	}
}

var ports interface{}

func (scan *Scanner) argumentsControl(arguments map[string]interface{}) bool {

	if arguments["<ip>"] != nil {
		var ipRange interface{}
		ipRange = arguments["<ip>"]
		ip, _ := ipRange.(string)
		matchIP := false
		matchIP, _ = regexp.MatchString(`^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$`, ip)
		if matchIP != false {
			scan.IP = arguments["<ip>"].(string)
		} else {
			color.Warn.Prompt("--ip IP not valid  e.g => 127.0.0.0/24")
			return true
		}
	}

	if arguments["<ports>"] != nil {
		ports = arguments["<ports>"]
		var ports []string = ports.([]string)
		ports = strings.Split(ports[0], ",")
		var Ports []string
		for i := 0; i < len(ports); i++ {
			matchPorts := false
			matchPorts, _ = regexp.MatchString(`^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$`, ports[i])
			if matchPorts != false {
				Ports = append(Ports, ports[i])
			} else {
				color.Warn.Prompt("--ports Port not valid e.g => 80,443,8080")
				return true
			}
		}
		scan.Ports = Ports

	}

	if arguments["--timeout"] != nil {
		timeout := arguments["--timeout"].(string)
		timeInt, _ := strconv.Atoi(timeout)
		if timeInt < 100 {
			color.Warn.Prompt("--timeout Request timeout must be greater than or equal to 100 ")
			return true
		}
		scan.RTime = timeInt

	}

	if arguments["--wcdb"] != nil {
		wcdbCome := arguments["--wcdb"].(string)
		if wcdbCome == "true" {
			scan.wcdb = true
		} else if wcdbCome == "false" {
			scan.wcdb = false
		} else {
			color.Warn.Prompt("--wcdb must be true or false")
			return true
		}
	}

	if arguments["--entries"] != nil {
		entriesCome := arguments["--entries"].(string)
		if entriesCome == "true" {
			scan.entries = true
		} else if entriesCome == "false" {
			scan.entries = false
		} else {
			color.Warn.Prompt("--entries must be true or false")
			return true
		}
	}
	if arguments["--ssl"] != nil {
		sslCome := arguments["--ssl"].(string)
		if sslCome == "true" {
			scan.ssl = true
		} else if sslCome == "false" {
			scan.ssl = false
		} else {
			color.Warn.Prompt("--ssl must be true or false")
			return true
		}
	}

	if arguments["--verbose"] != nil {
		verboseCome := arguments["--verbose"].(string)
		if verboseCome == "true" {
			scan.verbose = true
		} else if verboseCome == "false" {
			scan.verbose = false
		} else {
			color.Warn.Prompt("--verbose must be true or false")
			return true
		}
	}

	if scan.entries == false && scan.wcdb == false {
		color.Warn.Prompt("--entries and --wcdb can't be false at same time")
		return true
	}
	return false

}

//Hosts Hosts
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
