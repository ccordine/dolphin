// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

// Run only in a disposable container. This checks the real Qt entry point with
// a synthetic PowerPC loop and private settings, without a display or user data.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 65536 - b.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

func launch(binaryPath, root, name string, controller []string, accepted bool) error {
	profile := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Join(profile, "Config"), 0700); err != nil {
		return err
	}
	settings := filepath.Join(profile, "Config", "GCPadNew.ini")
	retained := "[GCPad1]\nDevice = SDL/0/Owner fixture\nButtons/A = `Button E`\n"
	if err := os.WriteFile(settings, []byte(retained), 0600); err != nil {
		return err
	}
	args := []string{"-u", profile, "-b", "-e", filepath.Join(root, "loop.dol"),
		"-v", "Null", "-C", "Dolphin.Core.CPUCore=0", "-C", "Dolphin.DSP.Backend=Null",
		"-C", "Dolphin.Interface.ConfirmStop=False"}
	args = append(args, controller...)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binaryPath, args...)
	command.Env = append(os.Environ(), "QT_QPA_PLATFORM=offscreen", "DOLPHIN_EMU_USERPATH="+profile)
	var output boundedOutput
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if accepted {
			return fmt.Errorf("%s: valid launch ended before startup: %v\n%s", name, err, output.String())
		}
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			return fmt.Errorf("%s: malformed controller selection was not rejected: %v\n%s", name, err, output.String())
		}
	case <-time.After(3 * time.Second):
		_ = command.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-ctx.Done():
			<-done
		}
		if !accepted {
			return fmt.Errorf("%s: malformed controller selection started the emulator", name)
		}
	}
	data, err := os.ReadFile(settings)
	if err != nil {
		return err
	}
	for _, value := range []string{"Device = SDL/0/Owner fixture", "Buttons/A = `Button E`"} {
		if !strings.Contains(string(data), value) {
			return fmt.Errorf("%s: launch changed retained controller settings", name)
		}
	}
	fmt.Printf("PASS %s\n", name)
	return nil
}

func main() {
	binaryPath := flag.String("binary", "", "actual Qt Dolphin executable")
	flag.Parse()
	root, err := os.MkdirTemp("", "dolphin-controller-check-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	program := make([]byte, 0x120)
	for offset, value := range map[int]uint32{0: 0x100, 0x48: 0x80003100, 0x90: 32, 0xe0: 0x80003100, 0x100: 0x48000000} {
		binary.BigEndian.PutUint32(program[offset:], value)
	}
	if err := os.WriteFile(filepath.Join(root, "loop.dol"), program, 0600); err != nil {
		panic(err)
	}
	failed := false
	for _, test := range []struct {
		name       string
		controller []string
		accepted   bool
	}{
		{"absent", nil, true},
		{"explicit", []string{"--controller-device=1=physical"}, true},
		{"invalid-port", []string{"--controller-device=0=physical"}, false},
		{"duplicate-port", []string{"--controller-device=1=physical", "--controller-device=1=physical"}, false},
	} {
		if err := launch(*binaryPath, root, test.name, test.controller, test.accepted); err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}
