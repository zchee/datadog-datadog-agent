package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/DataDog/datadog-agent/comp/core/pid/hashicorploader"
	"github.com/DataDog/datadog-agent/comp/core/pid/pidimpl"
)

func main() {
	// We don't want to see the plugin logs.
	log.SetOutput(ioutil.Discard)

	pid, err := hashicorploader.NewPluginPID(pidimpl.Dependencies{
		Params: pidimpl.NewParams("/tmp/pidfile"),
	})

	if err != nil {
		fmt.Printf("error: %+v\n", err)
		os.Exit(1)
	}
	path, err := pid.PIDFilePath()
	fmt.Println("---------------------", path, "****", err)
	os.Exit(0)
}
