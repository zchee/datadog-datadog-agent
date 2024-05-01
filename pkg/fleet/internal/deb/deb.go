// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package deb provides a way to create and install dumb deb packages that conflict with existing packages.
package deb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/xor-gate/ar"
)

// Deb writes a new deb package to the given writer using the given info.
func Deb(name string, version string, conflicts []string, out io.Writer) error {
	mtime := time.Now()

	dataTar, err := createDataTar()
	if err != nil {
		return fmt.Errorf("cannot create data tarball: %w", err)
	}
	controlTar, err := createControlTar(name, version, conflicts, mtime)
	if err != nil {
		return fmt.Errorf("cannot create control tarball: %w", err)
	}

	aw := ar.NewWriter(out)
	err = aw.WriteGlobalHeader()
	if err != nil {
		return fmt.Errorf("cannot write global header: %w", err)
	}
	err = writeArFile(aw, "debian-binary", []byte("2.0\n"), mtime)
	if err != nil {
		return fmt.Errorf("cannot pack debian-binary: %w", err)
	}
	err = writeArFile(aw, "control.tar.gz", controlTar, mtime)
	if err != nil {
		return fmt.Errorf("cannot add control.tar.gz to deb: %w", err)
	}
	err = writeArFile(aw, "data.tar.gz", dataTar, mtime)
	if err != nil {
		return fmt.Errorf("cannot add data.tar.gz to deb: %w", err)
	}
	return nil
}

func createDataTar() ([]byte, error) {
	var archive bytes.Buffer
	gw := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gw)
	err := tw.Close()
	if err != nil {
		return nil, err
	}
	err = gw.Close()
	if err != nil {
		return nil, err
	}
	return archive.Bytes(), nil
}

func createControlTar(pkg string, version string, conflicts []string, mtime time.Time) ([]byte, error) {
	var archive bytes.Buffer
	gw := gzip.NewWriter(&archive)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	control := buildControlFile(pkg, version, conflicts)
	md5sums := []byte(``)

	err := writeTarFile(tw, "./control", control, mtime)
	if err != nil {
		return nil, fmt.Errorf("cannot write control file to tar: %w", err)
	}
	err = writeTarFile(tw, "./md5sums", md5sums, mtime)
	if err != nil {
		return nil, fmt.Errorf("cannot write md5sums file to tar: %w", err)
	}
	err = tw.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot close tar writer: %w", err)
	}
	err = gw.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot close gzip writer: %w", err)
	}
	return archive.Bytes(), nil
}

func writeTarFile(tw *tar.Writer, name string, content []byte, mtime time.Time) error {
	err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0644,
		Size:     int64(len(content)),
		ModTime:  mtime,
		Typeflag: tar.TypeReg,
		Format:   tar.FormatGNU,
	})
	if err != nil {
		return err
	}
	_, err = tw.Write(content)
	return err
}

func writeArFile(w *ar.Writer, name string, content []byte, mtime time.Time) error {
	err := w.WriteHeader(&ar.Header{
		Name:    name,
		ModTime: mtime,
		Mode:    0644,
		Size:    int64(len(content)),
	})
	if err != nil {
		return err
	}
	_, err = w.Write(content)
	return err
}

func buildControlFile(pkg string, version string, conflicts []string) []byte {
	pkg = strings.TrimSpace(pkg)
	version = strings.TrimSpace(version)
	for i, c := range conflicts {
		conflicts[i] = strings.TrimSpace(c)
	}
	return []byte(fmt.Sprintf(`
Package: %s
Version: %s
Section: utils
Priority: optional
Vendor: Datadog <package@datadoghq.com>
Maintainer: Datadog Packages <package@datadoghq.com>
Architecture: any
Multi-Arch: same
Homepage: https://www.datadoghq.com
Description: %s - Installed by the Datadog Installer
  This package is installed by the Datadog Installer during the installation of %s.
  It is made to conflict with the debian package of the same name.
  Note that uninstalling this package will not remove %s and may cause issues if you try to install the debian package later.
Conflicts: %s
`, pkg, version, pkg, pkg, pkg, strings.Join(conflicts, ", ")))
}
