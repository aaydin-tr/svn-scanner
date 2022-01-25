# Svn-Scanner

Svn-Scanner is a Golang tool that scans for .svn vulnerabilities. Svn-Scanner offers you the opportunity to scan through the ip range and different ports.
## Installation

Using Svn-Scanner is easy. First, use `go install` to install the latest version of the tool.

```bash
go install github.com/AbdurrahmanA/svn-scanner@latest
mv $GOPATH/bin/svn-scanner /usr/bin/
svn-scanner scan --ip 192.168.1.1/24 --ports 80,443
```

## Usage
	Examples:
	svn-scanner scan --ip 192.168.1.1/24 --ports 80,443

	Available Commands:
	  completion  Generate the autocompletion script for the specified shell
	  help        Help about any command
	  scan        Scan for .svn vulnerabilities

	Flags:
	      --config string   config file (default is $HOME/.svn-scanner.yaml)
	      --entries         Check .svn/entries
	  -h, --help            help for svn-scanner
	      --ip string       IP with subnetmask
	      --ports strings   Ports to scan
	      --ssl             Check https version
	      --threads int     How many threads will be used (default 12)
	      --timeout int     Scanner timeout for ip (default 10)
	  -t, --toggle          Help message for toggle
	      --verbose         You will see all result not just http code 200
	  -v, --version         version for svn-scanner
	      --wcdb            Check .svn/wc.db (default true)

	 
All result save in the output.txt. (Doesn't matter whether the scan is finished or not)
