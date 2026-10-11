// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

// Read-only adapter for bundled Mbed TLS's CMake configuration queries.
// The supplied script path is data; no Python is executed.
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

func query(data []byte, name string) (string, bool, error) {
	switch name {
	case "MBEDTLS_CTR_DRBG_USE_128_BIT_KEY", "MBEDTLS_TEST_NULL_ENTROPY", "MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED":
	default:
		return "", false, fmt.Errorf("unsupported CMake configuration query")
	}
	pattern := regexp.MustCompile(`(?m)^[\t ]*#[\t ]*define[\t ]+` + name + `(?:[\t ]+(.*))?$`)
	matches := pattern.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return "", false, nil
	}
	return strings.TrimSpace(string(matches[len(matches)-1][1])), true, nil
}

func main() {
	args := os.Args[1:]
	if len(args) != 5 || !strings.HasSuffix(args[0], "/scripts/config.py") || args[1] != "-f" || args[3] != "get" {
		fmt.Fprintln(os.Stderr, "expected the read-only Mbed TLS CMake query")
		os.Exit(2)
	}
	data, err := os.ReadFile(args[2])
	if err != nil || len(data) > 1<<20 {
		fmt.Fprintln(os.Stderr, "configuration header is unavailable or oversized")
		os.Exit(2)
	}
	value, active, err := query(data, args[4])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if !active {
		os.Exit(1)
	}
	if value != "" {
		fmt.Println(value)
	}
}
