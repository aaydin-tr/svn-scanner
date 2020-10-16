package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
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
}

var err = false
var empyt []byte
var ips []string

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
	svn-scanner.go --ip <ip> --ports <ports>... [--timeout <timeout> ] [--wcdb <wcdb> ] [--entries <entries> ] [--ssl <ssl>] [--verbose  <verbose>]
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
			maxTime = time.Duration((sub.GetNumberAddressableHosts()*len(scan.Ports)*scan.RTime)*2) * time.Millisecond
		} else {
			maxTime = time.Duration((sub.GetNumberAddressableHosts() * len(scan.Ports) * scan.RTime)) * time.Millisecond
		}

		color.Info.Prompt("IP Range => %s", sub.GetIPAddressRange())
		color.Info.Prompt("Network Size => %d", sub.GetNetworkSize())
		color.Info.Prompt("%d IP's will be scan", sub.GetNumberAddressableHosts())
		color.Info.Println("It will last", maxTime)

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

	count := 0
	for i := 0; i < len(tmp); i++ {
		for j := 0; j < len(scan.Ports); j++ {
			if scan.wcdb == true {
				if scan.ssl == true {
					StatusCode, _, err := fasthttp.GetTimeout(empyt, "https://"+tmp[i]+":"+scan.Ports[j]+"/.svn/wc.db", time.Duration(scan.RTime)*time.Millisecond)
					if err == nil {
						if scan.verbose == true {
							count++
							s := strconv.Itoa(StatusCode)
							ips = append(ips, tmp[i]+":"+scan.Ports[j]+" -> "+s)
						} else {
							if StatusCode == 200 {
								count++
								s := strconv.Itoa(StatusCode)
								ips = append(ips, tmp[i]+":"+scan.Ports[j]+" -> "+s)
							}
						}
					}
				}
				StatusCode, _, err := fasthttp.GetTimeout(empyt, "http://"+tmp[i]+":"+scan.Ports[j]+"/.svn/wc.db", time.Duration(scan.RTime)*time.Millisecond)
				if err == nil {
					if scan.verbose == true {
						count++
						s := strconv.Itoa(StatusCode)
						ips = append(ips, tmp[i]+":"+scan.Ports[j]+" -> "+s)
					} else {
						if StatusCode == 200 {
							count++
							s := strconv.Itoa(StatusCode)
							ips = append(ips, tmp[i]+":"+scan.Ports[j]+" -> "+s)
						}
					}
				}
			}
			if scan.entries == true {
				if scan.ssl == true {
					StatusCode, _, err := fasthttp.GetTimeout(empyt, "https://"+tmp[i]+":"+scan.Ports[j]+"/.svn/entries", time.Duration(scan.RTime)*time.Millisecond)
					if err == nil {
						if scan.verbose == true {
							count++
							s := strconv.Itoa(StatusCode)
							ips = append(ips, tmp[i]+":"+scan.Ports[j]+" -> "+s)
						} else {
							if StatusCode == 200 {
								count++
								s := strconv.Itoa(StatusCode)
								ips = append(ips, tmp[i]+":"+scan.Ports[j]+" -> "+s)
							}
						}
					}
				}
				StatusCode, _, err := fasthttp.GetTimeout(empyt, "http://"+tmp[i]+":"+scan.Ports[j]+"/.svn/entries", time.Duration(scan.RTime)*time.Millisecond)
				if err == nil {
					if scan.verbose == true {
						count++
						s := strconv.Itoa(StatusCode)
						ips = append(ips, tmp[i]+":"+scan.Ports[j]+" -> "+s)
					} else {
						if StatusCode == 200 {
							count++
							s := strconv.Itoa(StatusCode)
							ips = append(ips, tmp[i]+":"+scan.Ports[j]+" -> "+s)
						}
					}
				}
			}
			fmt.Printf("\rCount -> %d -> %s -> %d ", i, tmp[i]+":"+scan.Ports[j], count)
		}
	}
	writeLines(ips, "output.txt")

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
