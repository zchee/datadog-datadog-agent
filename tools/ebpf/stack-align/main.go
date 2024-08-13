// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"
)

var (
	useDebugFiles bool
	buildDir      string
)

func init() {
	flag.BoolVar(&useDebugFiles, "use-debug-files", false, "use .o.debug files instead of .o files if present")
	flag.StringVar(&buildDir, "build-dir", "", "top-level directory where eBPF object files should be checked")
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}

func run() error {
	if buildDir == "" {
		return fmt.Errorf("usage: stack-align -build-dir <build-dir> [-use-debug-files]")
	}

	disPath, err := exec.LookPath("llvm-dis")
	if err != nil {
		return fmt.Errorf("could not find llvm-dis: %w", err)
	}
	paholePath, err := exec.LookPath("pahole")
	if err != nil {
		return fmt.Errorf("could not find pahole: %w", err)
	}

	misalignedCount := 0
	bcPaths, err := glob(buildDir, `.*\.bc$`)
	if err != nil {
		return fmt.Errorf("glob: %w", err)
	}
	for _, bcPath := range bcPaths {
		structNames, err := oneAlignedStructs(disPath, bcPath)
		if err != nil {
			return fmt.Errorf("find `align 1` structs: %w", err)
		}
		if len(structNames) == 0 {
			continue
		}

		objFile := strings.TrimSuffix(bcPath, filepath.Ext(bcPath)) + ".o"
		if useDebugFiles {
			if _, err := os.Stat(objFile + ".debug"); err == nil {
				objFile += ".debug"
			}
		}
		for _, structName := range structNames {
			size, err := structSize(paholePath, structName, objFile)
			if err != nil {
				return err
			}
			if size > 8 && size%8 != 0 {
				misalignedCount += 1
				fmt.Printf("struct `%s` in %s is misaligned and needs `__align_stack_8`.\nExample fix: `struct %s x __align_stack_8;`\n\n", structName, objFile, structName)
			}
		}
	}

	if misalignedCount > 0 {
		return fmt.Errorf("%d structs are misaligned\n", misalignedCount)
	}
	return nil
}

func oneAlignedStructs(disPath string, path string) ([]string, error) {
	var buf, errBuf bytes.Buffer
	discmd := exec.Command(disPath, "-o", "-", path)
	discmd.Stdout = &buf
	discmd.Stderr = &errBuf

	if err := discmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w\n%s", disPath, strings.Join(discmd.Args, " "), err, errBuf.String())
	}

	alignRegexp := regexp.MustCompile(`alloca %struct.([^,]+), align [124],`)
	structNames := make(map[string]struct{})
	rdr := bufio.NewScanner(&buf)
	for rdr.Scan() {
		line := rdr.Text()
		if match := alignRegexp.FindStringSubmatch(line); match != nil {
			structNames[match[1]] = struct{}{}
		}
	}

	return maps.Keys(structNames), nil
}

func structSize(paholePath string, structName string, objFile string) (uint64, error) {
	var buf, errBuf bytes.Buffer
	paholeCmd := exec.Command(paholePath, "-C", structName, objFile)
	paholeCmd.Stdout = &buf
	paholeCmd.Stderr = &errBuf

	if err := paholeCmd.Run(); err != nil {
		return 0, fmt.Errorf("%s: %w\n%s", paholeCmd, err, errBuf.String())
	}

	sizePattern := "/* size: "
	rdr := bufio.NewScanner(&buf)
	for rdr.Scan() {
		line := rdr.Text()
		if sidx := strings.Index(line, sizePattern); sidx != -1 {
			substr := line[sidx+len(sizePattern):]
			if eidx := strings.Index(substr, ","); eidx != -1 {
				size, err := strconv.ParseUint(substr[:eidx], 10, 64)
				if err != nil {
					return 0, fmt.Errorf("parse size: %s: %w", line[sidx+len(sizePattern):], err)
				}
				return size, nil

			}
		}
	}
	return 0, fmt.Errorf("missing struct %q size in %q", structName, objFile)
}

func glob(dir, filePattern string) ([]string, error) {
	var matches []string

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		present, err := regexp.Match(filePattern, []byte(d.Name()))
		if err != nil {
			return fmt.Errorf("file regexp match: %s", err)
		}

		if d.IsDir() || !present {
			return nil
		}
		matches = append(matches, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}
