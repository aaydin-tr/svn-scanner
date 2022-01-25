package cmd

import (
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/gookit/color"
)

var status bool

func (scan *Scanner) Validate() {
	status = false

	// all Validate functions
	validateMap := map[string]string{
		"ValidateIPBlock":        "ValidateIPBlock",
		"ValidatePorts":          "ValidatePorts",
		"ValidateTimeout":        "ValidateTimeout",
		"ValidateWcdbAndEntries": "ValidateWcdbAndEntries",
	}

	ScannerType := reflect.TypeOf(&Scanner{})
	for i := 0; i < ScannerType.NumMethod(); i++ {
		method := ScannerType.Method(i)
		// if method.Name in validationMethods run method
		if validateMap[method.Name] != "" {
			method.Func.Call([]reflect.Value{reflect.ValueOf(scan)})
		}
	}

	if status == true {
		os.Exit(1)
	}

}

// validate ıp block
func (scan *Scanner) ValidateIPBlock() {
	matchIP, _ := regexp.MatchString(`^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$`, scan.IP)
	if matchIP == false {
		status = true
		color.Warn.Prompt("--ip IP not valid  e.g => 127.0.0.0/24")
	}
}

func (scan *Scanner) ValidatePorts() {
	var ports []string = scan.Ports
	ports = strings.Split(ports[0], ",")
	var Ports []string
	for i := 0; i < len(ports); i++ {
		matchPorts, _ := regexp.MatchString(`^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$`, ports[i])
		if matchPorts != false {
			Ports = append(Ports, ports[i])
		} else {
			status = true
			color.Warn.Prompt("--ports Port not valid e.g => 80,443,8080")
		}
	}
}

func (scan *Scanner) ValidateTimeout() {
	timeout := scan.RTime
	if timeout < 1 {
		status = true
		color.Warn.Prompt("--timeout Request timeout must be at least 1 second")
	}
}

// just in case
func (scan *Scanner) ValidateWcdbAndEntries() {
	if scan.wcdb == false && scan.entries == false {
		status = true
		color.Warn.Prompt("--entries and --wcdb can't be false at same time")
	}
}
