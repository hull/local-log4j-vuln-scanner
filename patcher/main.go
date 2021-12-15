package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hillu/local-log4j-vuln-scanner/patching"
)

func log(a ...interface{}) {
	_, err := fmt.Fprintln(os.Stderr, a...)
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) < 3 {
		log("usage: " + filepath.Base(os.Args[0]) + ": <file> <backupdir>")
		os.Exit(1)
	}

	source, backupDir := os.Args[1], os.Args[2]
	if err := patching.PatchAndSwap(source, backupDir); err != nil {
		log(err.Error())
		os.Exit(1)
	}
}
