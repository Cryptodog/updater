//go:debug tarinsecurepath=0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func extractTarGz(tarGzData []byte, destination string, stripComponents int) error {
	buf := bytes.NewBuffer(tarGzData)
	gzipReader, err := gzip.NewReader(buf)
	if err != nil {
		return err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Skip pax_global_header entries
		if header.Name == "pax_global_header" {
			continue
		}

		// Calculate the target path by stripping components
		target := header.Name
		if stripComponents > 0 {
			components := strings.SplitN(target, string(filepath.Separator), stripComponents+1)
			if len(components) > stripComponents {
				target = strings.Join(components[stripComponents:], string(filepath.Separator))
			} else {
				target = ""
			}
		}

		// Get the full path for the file
		target = filepath.Join(destination, target)

		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory if it doesn't exist
			if err := os.MkdirAll(target, os.ModePerm); err != nil {
				return err
			}

		case tar.TypeReg:
			// Create file
			file, err := os.Create(target)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(file, tarReader); err != nil {
				return err
			}

		default:
			return fmt.Errorf("unsupported file type: %v in %v", header.Typeflag, header.Name)
		}
	}

	return nil
}
