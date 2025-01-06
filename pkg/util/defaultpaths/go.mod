module github.com/DataDog/datadog-agent/pkg/util/defaultpaths

go 1.22.0

replace (
	github.com/DataDog/datadog-agent/pkg/util/executable => ../../../pkg/util/executable
	github.com/DataDog/datadog-agent/pkg/util/log => ../../../pkg/util/log
	github.com/DataDog/datadog-agent/pkg/util/scrubber => ../../../pkg/util/scrubber
	github.com/DataDog/datadog-agent/pkg/util/winutil => ../../../pkg/util/winutil
)

require (
	github.com/DataDog/datadog-agent/pkg/util/executable v0.62.0-rc.2
	github.com/DataDog/datadog-agent/pkg/util/log v0.62.0-rc.2
	github.com/DataDog/datadog-agent/pkg/util/winutil v0.62.0-rc.2
	golang.org/x/sys v0.28.0
)

require (
	github.com/DataDog/datadog-agent/pkg/util/scrubber v0.62.0-rc.2 // indirect
	github.com/DataDog/datadog-agent/pkg/version v0.62.0-rc.2 // indirect
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/DataDog/datadog-agent/pkg/version => ../../version
