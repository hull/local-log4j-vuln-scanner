package patching

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"github.com/hillu/local-log4j-vuln-scanner/filter"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func log(a ...interface{}) {
	_, err := fmt.Fprintln(os.Stderr, a...)
	if err != nil {
		panic(err)
	}
}

func patch(source, dest string, examineV1 bool) error {
	zr, err := zip.OpenReader(source)
	if err != nil {
		log("open (read)", source, err)
		os.Exit(1)
	}
	defer func(zr *zip.ReadCloser) {
		_ = zr.Close()
	}(zr)

	of, err := os.Create(dest)
	if err != nil {
		log("open (write): ", dest, err)
		return err
	}

	zw := zip.NewWriter(of)
	for _, member := range zr.File {
		r, err := member.Open()
		if err != nil {
			log("open (read): ", source, member.Name, err)
			if err = discardZip(dest, of, zw); err != nil {
				return err
			}
		}
		buf := bytes.NewBuffer(nil)
		if _, err := io.Copy(buf, r); err != nil { //nolint:gosec
			log("read: ", source, member.Name, err)
			_ = discardZip(dest, of, zw)
			return err
		}
		content := buf.Bytes()

		if desc := filter.IsVulnerableClass(content, member.Name, examineV1); desc != "" {
			fmt.Printf("Filtering out %s (%s)\n", member.Name, desc)
			_ = r.Close()
		} else {
			w, err := zw.Create(member.Name)
			if err != nil {
				log("open (write): ", dest, member.Name, err)
				_ = discardZip(dest, of, zw)
				return err
			}

			if _, err := io.Copy(w, buf); err != nil {
				log("write: ", dest, member.Name, err)
				_ = discardZip(dest, of, zw)
				return err
			}
			_ = r.Close()
		}
	}

	if err := zw.Close(); err != nil {
		log("finalize:", dest, err)
	}

	return of.Close()
}

func backupFile(src string, dest string) error {
	fileInfo, err := os.Stat(src)
	if err != nil {
		return errors.New("failed to stat source file: " + err.Error())
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name: src,
		Mode: int64(fileInfo.Mode()),
		Size: fileInfo.Size(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return errors.New("failed to write source file header" + err.Error())
	}
	srcBytes, err := ioutil.ReadFile(src)
	if err != nil {
		return errors.New("failed to read source file" + err.Error())
	}
	if _, err := tw.Write(srcBytes); err != nil {
		return errors.New("failed to write source to tar archive" + err.Error())
	}
	if err := tw.Close(); err != nil {
		return errors.New("failed to close tar archive" + err.Error())
	}

	return ioutil.WriteFile(dest, buf.Bytes(), 0600)
}

func PatchAndSwap(source, backupDir string) (err error) {
	success := false

	sourceWithLeadingDotsAndSlashesTrimed := strings.TrimLeft(strings.TrimLeft(strings.TrimLeft(source, ".."), "."), "/")
	backupFileName := strings.ReplaceAll(sourceWithLeadingDotsAndSlashesTrimed, "/", "_") +
		"-" + strconv.FormatInt(time.Now().Unix(), 10) + ".tar"
	backup := filepath.Join(backupDir, backupFileName)
	dest := source + ".new"

	defer func() {
		if !success {
			log("Removing backup file at ", backup)
			_ = os.Remove(backup)
		}
	}()

	sourceFileInfo, err := os.Stat(source)
	if err != nil {
		return errors.New("failed stat-ing source file: " + err.Error())
	}
	sourceFileStat, ok := sourceFileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("failed getting source file uid/gid: " + err.Error())
	}

	// Backup the source file
	log("Backing up ", source, " into ", backupDir, " as ", backup)

	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return errors.New("failed creating backup dir: " + err.Error())
	}
	if err := backupFile(source, backup); err != nil {
		return errors.New("failed source backup: " + err.Error())
	}

	// Patch source into the temp file
	log("Patching ", source, " into ", dest)
	err = patch(source, dest, true)
	if err != nil {
		_ = os.Remove(backup)
		return errors.New("failed patching source: " + err.Error())
	}

	if err := os.Chown(dest, int(sourceFileStat.Uid), int(sourceFileStat.Gid)); err != nil {
		return errors.New("failed setting file owner on target: " + err.Error())
	}

	if err := os.Chmod(dest, sourceFileInfo.Mode()); err != nil {
		return errors.New("failed setting file mode on target: " + err.Error())
	}

	// Replace source with patched temp file
	log("Replacing source ", source, " with patched version from ", dest)
	err = os.Rename(dest, source)
	if err != nil {
		_ = os.Remove(backup)
		return errors.New("failed to stage patched file : " + err.Error())
	}

	success = true

	log("Patching done for " + source)

	return nil
}

func discardZip(dest string, of *os.File, zw *zip.Writer) error {
	log("Removing output file", dest)
	if err := zw.Close(); err != nil {
		return err
	}
	if err := of.Close(); err != nil {
		return err
	}

	return nil
}
