package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/DataDog/datadog-agent/comp/core/pid/hashicorploader"
)

func main() {
	// We don't want to see the plugin logs.
	log.SetOutput(ioutil.Discard)

	if err := hashicorploader.CreateComponent(); err != nil {
		fmt.Printf("error: %+v\n", err)
		os.Exit(1)
	}

	os.Exit(0)
}
