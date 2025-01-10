module github.com/DataDog/datadog-agent/comp/core/flare/types

go 1.22.0

replace github.com/DataDog/datadog-agent/comp/core/flare/builder => ../builder

require (
	github.com/DataDog/datadog-agent/comp/core/flare/builder v0.61.0
	go.uber.org/fx v1.22.2
)

require (
	github.com/stretchr/testify v1.10.0 // indirect
	go.uber.org/dig v1.18.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
)
