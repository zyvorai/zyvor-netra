// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

//go:build !linux

package bpfattach

import "errors"

// NewSource reports that BPF attachments are a Linux facility.
func NewSource() Source { return unsupported{} }

type unsupported struct{}

var errLinux = errors.New("BPF attachment inventory requires Linux")

func (unsupported) Links() ([]LinkInfo, error)            { return nil, errLinux }
func (unsupported) TCX(int, bool) ([]uint32, bool, error) { return nil, false, errLinux }
func (unsupported) TC(int, bool) ([]TCFilter, error)      { return nil, errLinux }
func (unsupported) ProgramName(uint32) (string, error)    { return "", errLinux }
