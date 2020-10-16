# Svn-Scanner

Svn-Scanner is a Golang library that scans for .svn vulnerabilities. Svn-Scanner offers you the opportunity to scan through the ip range and different ports.
## Installation

Using Svn-Scanner is easy. First, use go get to install the latest version of the library.

```bash
go get "github.com/AbdurrahmanA/svn-scanner"

```

## Usage
	Options:
	  -h --help     Show this screen.
	  --version     Show version.
	  --ip     	    IP with subnetmask.
	  --ports     	Ports to scan.
	  --timeout 	Scanner timeout for ip [default: 1000 ].
	  --wcdb 	    Check .svn/wc.db [default: true].
	  --entries 	Check .svn/entries [default: false].
	  --ssl 	    Check https version [default: false].
	  --verbose 	You will see all result not just http code 200 [default: false].
	 
```bash
go run svn-scanner.go --ip 127.0.0.1/24 --port 80,443 --timeout 100 --verbose true

```
All result save in the output.txt. (Doesn't matter whether the scan is finished or not)


## License
[MIT](https://choosealicense.com/licenses/mit/)