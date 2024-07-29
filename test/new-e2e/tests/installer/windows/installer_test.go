// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package installerwindows implements E2E tests for the Datadog Installer on Windows
package installerwindows

import (
	"embed"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	awsHostWindows "github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments/aws/host/windows"
	"github.com/DataDog/datadog-agent/test/new-e2e/tests/installer"
	"github.com/DataDog/datadog-agent/test/new-e2e/tests/windows/common"
	"github.com/DataDog/datadog-agent/test/new-e2e/tests/windows/common/agent"
	"github.com/DataDog/datadog-agent/test/new-e2e/tests/windows/common/pipeline"
	"os"
	"testing"
)

//go:embed fixtures/sample_config
var fixturesFS embed.FS

type testInstallerSuite struct {
	baseSuite
}

// TestInstaller tests the installation of the Datadog Installer on a system.
func TestInstaller(t *testing.T) {
	e2e.Run(t, &testInstallerSuite{}, e2e.WithProvisioner(awsHostWindows.ProvisionerNoAgentNoFakeIntake()))
}

// TestInstalls tests installing and uninstalling the latest version of the Datadog Installer from the pipeline.
func (suite *testInstallerSuite) TestInstalls() {
	suite.Run("Fresh install", func() {
		// Arrange

		// Act
		suite.Require().NoError(suite.installer.Install())

		// Assert
		suite.Require().Host(suite.Env().RemoteHost).
			HasBinary(InstallerBinaryPath).
			WithSignature(agent.GetCodeSignatureThumbprints()).
			WithVersionMatchPredicate(func(version string) {
				suite.Require().NotEmpty(version)
			}).
			HasAService(InstallerServiceName).
			// the service cannot start because of the missing API key
			WithStatus("Stopped").
			WithIdentity(common.GetIdentityForSID("S-1-5-18"))
	})

	suite.Run("Start service with a configuration file", func() {
		// Arrange
		suite.Env().RemoteHost.CopyFileFromEmbedded(fixturesFS, "fixtures/sample_config", InstallerConfigPath)

		// Act
		suite.Require().NoError(common.StartService(suite.Env().RemoteHost, InstallerServiceName))

		// Assert
		suite.Require().Host(suite.Env().RemoteHost).
			HasAService(InstallerServiceName).
			WithStatus("Running")
	})

	suite.Run("Uninstall", func() {
		// Arrange

		// Act
		suite.Require().NoError(suite.installer.Uninstall())

		// Assert
		suite.Require().Host(suite.Env().RemoteHost).
			NoFileExists(InstallerBinaryPath).
			HasNoService(InstallerServiceName).
			FileExists(InstallerConfigPath)
	})

	suite.Run("Install with existing configuration file", func() {
		// Arrange

		// Act
		suite.Require().NoError(suite.installer.Install())

		// Assert
		suite.Require().Host(suite.Env().RemoteHost).
			HasAService(InstallerServiceName).
			WithStatus("Running")
	})

	suite.Run("Repair", func() {
		// Arrange
		suite.Require().NoError(common.StopService(suite.Env().RemoteHost, InstallerServiceName))
		suite.Env().RemoteHost.Remove(InstallerBinaryPath)

		// Act
		suite.Require().NoError(suite.installer.Install())

		// Assert
		suite.Require().Host(suite.Env().RemoteHost).
			HasAService(InstallerServiceName).
			WithStatus("Running")
	})
}

// TestUpgrades tests upgrading the stable version of the Datadog Installer to the latest from the pipeline.
func (suite *testInstallerSuite) TestUpgrades() {
	// Arrange
	suite.Require().NoError(suite.installer.Install(WithInstallerURLFromInstallersJSON(pipeline.AgentS3BucketTesting, pipeline.StableChannel, installer.StableVersionPackage)))
	// sanity check: make sure we did indeed install the stable version
	suite.Require().Host(suite.Env().RemoteHost).
		HasBinary(InstallerBinaryPath).
		// Don't check the binary signature because it could have been updated since the last stable was built
		WithVersionEqual(installer.StableVersion)

	// Act
	// Install "latest" from the pipeline
	suite.Require().NoError(suite.installer.Install())

	// Assert
	suite.Require().Host(suite.Env().RemoteHost).
		HasBinary(InstallerBinaryPath).
		WithSignature(agent.GetCodeSignatureThumbprints()).
		WithVersionMatchPredicate(func(version string) {
			pipelineVersion := os.Getenv("CURRENT_AGENT_VERSION")
			if pipelineVersion == "" {
				suite.Require().NotEqual(installer.StableVersion, version, "upgraded version should be different than stable version")
			} else {
				suite.Require().Equal(pipelineVersion, version, "upgraded version should be equal to pipeline version")
			}
		})
}
