// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package postgres

import (
	"bytes"
)

// postgresParameters represents the Postgres parameters from Postgres
// StartupMessage. This is a map from parameter name to parameters value.
type postgresParameters map[string]string

// parsePostgresParameters parses the request fragment from startup
// events, and returns a Go map of the parameters.
func parsePostgresParameters(fragment []byte) postgresParameters {
	result := make(postgresParameters)

	// Postgres parameters are represented as C strings pairs. The
	// first is the parameter name, the second is the parameter value.
	parameters := bytes.Split(fragment, []byte{0})

	for j := 0; j+1 < len(parameters); j += 2 {
		result[string(parameters[j])] = string(parameters[j+1])
	}

	return result
}

// getDatabaseName returns the Postgres database name using parsed Postgres parameters.
//
// The Postgres protocol spec states the following rules for getting the database name:
// - Look for a "database" parameter. If present, its value is the database name.
// - If there is no "database" parameter, the "user" parameter is used as the database name.
//
// Note: the only mandatory parameter in a Postgres StartupMessage is the "user" parameter.
func (p postgresParameters) getDatabaseName() string {
	if p == nil {
		return ""
	}

	if dbName, ok := p["database"]; ok {
		return dbName
	}

	if userName, ok := p["user"]; ok {
		return userName
	}

	return ""
}
