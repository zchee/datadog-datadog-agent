// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//nolint:revive // TODO Fix revive linter
package start

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/DataDog/datadog-agent/comp/aggregator/diagnosesendermanager"
	"github.com/DataDog/datadog-agent/comp/aggregator/diagnosesendermanager/diagnosesendermanagerimpl"
	"github.com/DataDog/datadog-agent/comp/collector/collector"
	"github.com/DataDog/datadog-agent/comp/collector/collector/collectorimpl"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/hostname/hostnameimpl"
	log "github.com/DataDog/datadog-agent/comp/core/log/def"
	logfx "github.com/DataDog/datadog-agent/comp/core/log/fx"
	"github.com/DataDog/datadog-agent/comp/core/secrets"
	"github.com/DataDog/datadog-agent/comp/core/secrets/secretsimpl"
	noopTelemetry "github.com/DataDog/datadog-agent/comp/core/telemetry/noopsimpl"
	integrations "github.com/DataDog/datadog-agent/comp/logs/integrations/def"
	"github.com/DataDog/datadog-agent/comp/serializer/compression/compressionimpl"
	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	pkgcollector "github.com/DataDog/datadog-agent/pkg/collector"
	"github.com/DataDog/datadog-agent/pkg/serializer"
	"github.com/DataDog/datadog-agent/pkg/status/health"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/util/optional"
)

type CLIParams struct {
	confPath string
}

// MakeCommand returns the start subcommand for the 'dogstatsd' command.
func MakeCommand() *cobra.Command {
	cliParams := &CLIParams{}
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start Checks Agent",
		Long:  `Runs Checks Agent in the foreground`,
		RunE: func(*cobra.Command, []string) error {
			return RunChecksAgent(cliParams, "", start)
		},
	}

	// local flags
	startCmd.PersistentFlags().StringVarP(&cliParams.confPath, "cfgpath", "c", "", "path to directory containing datadog.yaml")

	return startCmd
}

func RunChecksAgent(cliParams *CLIParams, defaultConfPath string, fct interface{}) error {
	return fxutil.OneShot(fct,
		fx.Supply(cliParams),

		// Configuration
		fx.Supply(config.NewParams(
			defaultConfPath,
			config.WithConfFilePath(cliParams.confPath),
			config.WithConfigMissingOK(true),
			config.WithConfigName("datadog")),
		),
		config.Module(),

		// Logging
		logfx.Module(),
		fx.Supply(log.ForDaemon("CA", "log_file", "/var/log/datadog/checks-agent.log")),

		// Secrets management
		fx.Provide(func(comp secrets.Component) optional.Option[secrets.Component] {
			return optional.NewOption[secrets.Component](comp)
		}),
		fx.Supply(secrets.NewEnabledParams()),
		secretsimpl.Module(),
		noopTelemetry.Module(),
		collectorimpl.Module(),
		fx.Provide(func() optional.Option[serializer.MetricSerializer] {
			return optional.NewNoneOption[serializer.MetricSerializer]()
		}),
		diagnosesendermanagerimpl.Module(),
		fx.Provide(func(diagnoseSenderManager diagnosesendermanager.Component) (sender.SenderManager, error) {
			return diagnoseSenderManager.LazyGetSenderManager()
		}),
		compressionimpl.Module(),
		hostnameimpl.Module(),
	)
}

func start(
	cliParams *CLIParams,
	config config.Component,
	log log.Component,
	_ diagnosesendermanager.Component,
	collector collector.Component,
	sender sender.SenderManager,
) error {

	// Main context passed to components
	ctx, cancel := context.WithCancel(context.Background())

	defer StopAgent(cancel, log)

	// TODO: figure out how to initial.ize checks context
	// check.InitializeInventoryChecksContext(invChecks)

	pkgcollector.InitCheckScheduler(optional.NewOption(collector), sender, optional.NewNoneOption[integrations.Component]())

	stopCh := make(chan struct{})
	go handleSignals(stopCh, log)

	err := Run(ctx, cliParams, config, log)
	if err != nil {
		return err
	}

	// Block here until we receive a stop signal
	<-stopCh

	return nil
}

// Run starts the Logs agent server
func Run(ctx context.Context, cliParams *CLIParams, config config.Component, log log.Component) (err error) {
	if len(cliParams.confPath) == 0 {
		log.Infof("Config will be read from env variables")
	}

	if !config.IsSet("api_key") {
		err = log.Critical("no API key configured, exiting")
		return
	}

	return nil
}

// handleSignals handles OS signals, and sends a message on stopCh when an interrupt
// signal is received.
func handleSignals(stopCh chan struct{}, log log.Component) {
	// Setup a channel to catch OS signals
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM, syscall.SIGPIPE)

	// Block here until we receive the interrupt signal
	for signo := range signalCh {
		switch signo {
		case syscall.SIGPIPE:
			// By default systemd redirects the stdout to journald. When journald is stopped or crashes we receive a SIGPIPE signal.
			// Go ignores SIGPIPE signals unless it is when stdout or stdout is closed, in this case the agent is stopped.
			// We never want dogstatsd to stop upon receiving SIGPIPE, so we intercept the SIGPIPE signals and just discard them.
		default:
			log.Infof("Received signal '%s', shutting down...", signo)
			stopCh <- struct{}{}
			return
		}
	}
}

func StopAgent(cancel context.CancelFunc, log log.Component) {
	// retrieve the agent health before stopping the components
	// GetReadyNonBlocking has a 100ms timeout to avoid blocking
	health, err := health.GetReadyNonBlocking()
	if err != nil {
		log.Warnf("Logs Agent health unknown: %s", err)
	} else if len(health.Unhealthy) > 0 {
		log.Warnf("Some components were unhealthy: %v", health.Unhealthy)
	}

	// gracefully shut down any component
	cancel()

	log.Info("See ya!")
	log.Flush()
}
