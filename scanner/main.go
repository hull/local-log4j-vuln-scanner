package main

import (
	"archive/zip"
	"bytes"
	"flag"
	"fmt"
	"github.com/hillu/local-log4j-vuln-scanner/patching"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/hillu/local-log4j-vuln-scanner/filter"
)

var (
	logFile = os.Stdout
	errFile = os.Stderr
)

func handleJar(path string, ra io.ReaderAt, sz int64) {
	var vulnerable bool
	vulnerable = false
	if verbose {
		_, _ = fmt.Fprintf(errFile, "Inspecting %s...\n", path)
	}
	zr, err := zip.NewReader(ra, sz)
	if err != nil {
		_, _ = fmt.Fprintf(errFile, "can't open JAR file: %s (size %d): %v\n", path, sz, err)
		return
	}
	for _, file := range zr.File {
		switch strings.ToLower(filepath.Ext(file.Name)) {
		case ".class":
			fr, err := file.Open()
			if err != nil {
				_, _ = fmt.Fprintf(errFile, "can't open JAR file member for reading: %s (%s): %v\n", path, file.Name, err)
				continue
			}
			buf := bytes.NewBuffer(nil)
			if _, err = io.Copy(buf, fr); err != nil { //nolint:gosec
				_, _ = fmt.Fprintf(errFile, "can't read JAR file member: %s (%s): %v\n", path, file.Name, err)
				_ = fr.Close()
				continue
			}
			_ = fr.Close()
			if desc := filter.IsVulnerableClass(buf.Bytes(), file.Name, !ignoreV1); desc != "" {
				_, _ = fmt.Fprintf(logFile, "indicator for vulnerable component found in %s (%s): %s\n", path, file.Name, desc)
				vulnerable = true
				continue
			}

		case ".jar", ".war", ".ear":
			fr, err := file.Open()
			if err != nil {
				_, _ = fmt.Fprintf(errFile, "can't open JAR file member for reading: %s (%s): %v\n", path, file.Name, err)
				continue
			}
			buf, err := ioutil.ReadAll(fr)
			_ = fr.Close()
			if err != nil {
				_, _ = fmt.Fprintf(errFile, "can't read JAR file member: %s (%s): %v\n", path, file.Name, err)
			}
			handleJar(path+"::"+file.Name, bytes.NewReader(buf), int64(len(buf)))
		}
	}
	if vulnerable && applyPatches {
		err := patching.PatchAndSwap(path, backupDir)
		if err != nil {
			fmt.Println("Failed to patch Jar at " + path + " : " + err.Error())
			os.Exit(1)
		}
		fmt.Println("Patched Jar : " + path)
	}
}

type excludeFlags []string

func (flags *excludeFlags) String() string {
	return fmt.Sprint(*flags)
}

func (flags *excludeFlags) Set(value string) error {
	*flags = append(*flags, value)
	return nil
}

func (flags excludeFlags) Has(path string) bool {
	for _, exclude := range flags {
		if path == exclude {
			return true
		}
	}
	return false
}

var (
	excludes     excludeFlags
	verbose      bool
	logFileName  string
	backupDir    string
	quiet        bool
	ignoreV1     bool
	applyPatches bool
)

func main() {
	flag.Var(&excludes, "exclude", "paths to exclude")
	flag.BoolVar(&verbose, "verbose", false, "log every archive file considered")
	flag.StringVar(&logFileName, "log", "", "log file to write output to")
	flag.BoolVar(&quiet, "quiet", false, "no output unless vulnerable")
	flag.BoolVar(&ignoreV1, "ignore-v1", false, "ignore log4j 1.x versions")
	flag.BoolVar(&applyPatches, "apply-patches", false, "automatically patch vulnerability")
	flag.StringVar(&backupDir, "backup-dir", "", "directory to write backup files to")
	flag.Parse()

	if !quiet {
		_, _ = fmt.Fprintf(os.Stderr, "%s - a simple local log4j vulnerability scanner\n\n", filepath.Base(os.Args[0]))
	}

	if applyPatches && backupDir == "" {
		_, _ = fmt.Fprintf(os.Stderr, "--apply-patches needs --backup-dir to be set\n")
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s [--verbose] [--quiet] [--ignore-v1] [--apply-patches] [--backup-dir path] [--exclude path] [ paths ... ]\n", os.Args[0])
		os.Exit(1)
	}

	if logFileName != "" {
		f, err := os.Create(logFileName)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Could not create log file")
			os.Exit(2)
		}
		logFile = f
		errFile = f
		defer func(f *os.File) {
			_ = f.Close()
		}(f)
	}

	for _, root := range flag.Args() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				_, _ = fmt.Fprintf(errFile, "%s: %s\n", path, err)
				return nil
			}
			if excludes.Has(path) {
				return filepath.SkipDir
			}
			if info.IsDir() {
				return nil
			}
			switch ext := strings.ToLower(filepath.Ext(path)); ext {
			case ".jar", ".war", ".ear":
				f, err := os.Open(path)
				if err != nil {
					_, _ = fmt.Fprintf(errFile, "can't open %s: %v\n", path, err)
					return nil
				}
				defer func(f *os.File) {
					_ = f.Close()
				}(f)
				sz, err := f.Seek(0, io.SeekEnd)
				if err != nil {
					_, _ = fmt.Fprintf(errFile, "can't seek in %s: %v\n", path, err)
					return nil
				}
				if _, err := f.Seek(0, io.SeekEnd); err != nil {
					_, _ = fmt.Fprintf(errFile, "can't seek in %s: %v\n", path, err)
					return nil
				}
				handleJar(path, f, sz)
			default:
				return nil
			}
			return nil
		})
	}

	if !quiet {
		_, _ = fmt.Fprintf(os.Stderr, "\nScan finished\n")
	}
}
