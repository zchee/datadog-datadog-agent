package envs

import "github.com/DataDog/datadog-agent/pkg/util/log"

type EnvironmentVariables struct {
	vars map[string]string
}

var AllowedVars = map[string]struct{}{
	"CORECLR_ENABLE_PROFILING": {},
}

func NewEnvironmentVariables(vars map[string]string) EnvironmentVariables {
	return EnvironmentVariables{vars: vars}
}

func (ev *EnvironmentVariables) Get(name string) (string, bool) {
	if _, allowed := AllowedVars[name]; !allowed {
		log.Debug("accessing not allowed variable", name)
		return "", false
	}

	val, ok := ev.vars[name]
	return val, ok
}
