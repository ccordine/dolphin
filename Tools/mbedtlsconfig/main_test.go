// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

package main

import "testing"

func TestReadOnlyConfigurationQueries(t *testing.T) {
	name := "MBEDTLS_TEST_NULL_ENTROPY"
	for _, test := range []struct {
		data, value string
		active      bool
	}{
		{"#define MBEDTLS_TEST_NULL_ENTROPY\n", "", true},
		{" // #define MBEDTLS_TEST_NULL_ENTROPY\n", "", false},
		{"#define MBEDTLS_TEST_NULL_ENTROPY_DISABLED\n", "", false},
		{"#define MBEDTLS_TEST_NULL_ENTROPY 1\n", "1", true},
		{"#define OTHER 1\n", "", false},
	} {
		value, active, err := query([]byte(test.data), name)
		if err != nil || value != test.value || active != test.active {
			t.Fatalf("query %q: value=%q active=%v error=%v", test.data, value, active, err)
		}
	}
	if _, _, err := query(nil, "OTHER"); err == nil {
		t.Fatal("unsupported configuration query accepted")
	}
}
