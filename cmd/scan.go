/*
Copyright © 2022

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

type Scanner struct {
	IP      string
	Ports   []string
	RTime   int
	wcdb    bool
	entries bool
	ssl     bool
	verbose bool
	thread  int
}

var scan = &Scanner{
	wcdb:    true,
	entries: false,
	ssl:     false,
	verbose: false,
	thread:  12,
	RTime:   10,
}

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for .svn vulnerabilities",
	Long:  "Scan for .svn vulnerabilities",
	Run: func(cmd *cobra.Command, args []string) {
		scan.Validate()
		ipAndMask := strings.Split(scan.IP, "/")
		mask, _ := strconv.Atoi(ipAndMask[1])
		scanInfo(ipAndMask[0], mask)
		scan.Scan()
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	rootCmd.PersistentFlags().StringVar(&scan.IP, "ip", "", "IP with subnetmask")
	rootCmd.PersistentFlags().StringSliceVar(&scan.Ports, "ports", []string{}, "Ports to scan")
	rootCmd.PersistentFlags().IntVar(&scan.RTime, "timeout", 10, "Scanner timeout for ip")
	rootCmd.PersistentFlags().BoolVar(&scan.wcdb, "wcdb", true, "Check .svn/wc.db")
	rootCmd.PersistentFlags().BoolVar(&scan.entries, "entries", false, "Check .svn/entries")
	rootCmd.PersistentFlags().BoolVar(&scan.ssl, "ssl", false, "Check https version")
	rootCmd.PersistentFlags().BoolVar(&scan.verbose, "verbose", false, "You will see all result not just http code 200")
	rootCmd.PersistentFlags().IntVar(&scan.thread, "threads", 12, "How many threads will be used")

	rootCmd.MarkPersistentFlagRequired("ip")
	rootCmd.MarkPersistentFlagRequired("ports")

}
