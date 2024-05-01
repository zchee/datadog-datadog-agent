// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package dpkg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

// IsInstalled returns true if dpkg is installed.
func IsInstalled(ctx context.Context) (_ bool, err error) {
	span, _ := tracer.StartSpanFromContext(ctx, "dpkg_is_installed")
	defer func() { span.Finish(tracer.WithError(err)) }()

	_, err = exec.LookPath("dpkg")
	if errors.Is(err, exec.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot find dpkg: %w", err)
	}
	return true, nil
}

// InstallConflictPackage installs a new deb package with the given pkg and version that conflicts with the given packages.
func InstallConflictPackage(ctx context.Context, tmpDir string, pkg string, version string, conflicts ...string) (err error) {
	span, ctx := tracer.StartSpanFromContext(ctx, "dpkg_install_conflict_package")
	defer func() { span.Finish(tracer.WithError(err)) }()
	span.SetTag("package.name", pkg)
	span.SetTag("package.version", version)
	span.SetTag("package.conflicts", conflicts)

	pkg = conflictPackageName(pkg)
	tmpPath, err := os.CreateTemp(tmpDir, "*.deb")
	if err != nil {
		return fmt.Errorf("cannot create temporary deb file: %w", err)
	}
	defer os.Remove(tmpPath.Name())

	err = deb(pkg, version, conflicts, tmpPath)
	if err != nil {
		return fmt.Errorf("cannot create deb package: %w", err)
	}
	output, err := exec.CommandContext(ctx, "dpkg", "-i", tmpPath.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot install deb package: %w\n%s", err, output)
	}
	output, err = exec.CommandContext(ctx, "apt-mark", "hold", pkg).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot hold deb package: %w\n%s", err, output)
	}
	return nil
}

// RemoveConflictPackage removes the deb package with the given pkg.
func RemoveConflictPackage(ctx context.Context, pkg string) (err error) {
	span, ctx := tracer.StartSpanFromContext(ctx, "dpkg_remove_conflict_package")
	defer func() { span.Finish(tracer.WithError(err)) }()
	span.SetTag("package.name", pkg)

	pkg = conflictPackageName(pkg)
	output, err := exec.CommandContext(ctx, "apt-mark", "unhold", pkg).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot unhold deb package: %w\n%s", err, output)
	}
	output, err = exec.CommandContext(ctx, "dpkg", "-r", pkg).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot remove deb package: %w\n%s", err, output)
	}
	return nil
}

func conflictPackageName(pkg string) string {
	return fmt.Sprintf("%s-by-installer", pkg)
}
