// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// installCLICmd installs this netractl binary onto PATH (same idea as make install).
func installCLICmd(args []string) error {
	prefix := ""
	binDir := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--prefix":
			if i+1 >= len(args) {
				return fmt.Errorf("--prefix requires a value")
			}
			prefix = args[i+1]
			i++
		case "--bin-dir":
			if i+1 >= len(args) {
				return fmt.Errorf("--bin-dir requires a value")
			}
			binDir = args[i+1]
			i++
		case "-h", "--help":
			fmt.Println(`netractl install-cli [--prefix DIR] [--bin-dir DIR]
  Installs this netractl binary for PATH use (default: /usr/local/bin, or
  $HOME/.local/bin when /usr/local/bin is not writable). Same as: make install`)
			return nil
		default:
			return fmt.Errorf("unknown install-cli flag: %s", args[i])
		}
	}
	dest, err := resolveCLIInstallPath(prefix, binDir)
	if err != nil {
		return err
	}
	if err := installSelfCLI(dest); err != nil {
		return err
	}
	fmt.Printf("installed %s\n", dest)
	fmt.Println("Run: netractl status   (ensure the bin dir is on your PATH)")
	return nil
}

func resolveCLIInstallPath(prefix, binDir string) (string, error) {
	if binDir != "" {
		return filepath.Join(binDir, "netractl"), nil
	}
	if prefix == "" {
		prefix = strings.TrimSpace(os.Getenv("NETRA_CLI_PREFIX"))
	}
	if prefix != "" {
		return filepath.Join(prefix, "bin", "netractl"), nil
	}
	// Prefer /usr/local/bin when writable (or on Windows use user local).
	candidates := defaultCLIBinDirs()
	for _, dir := range candidates {
		dest := filepath.Join(dir, "netractl")
		if canWriteDir(dir) {
			return dest, nil
		}
		// Directory may not exist yet — parent writable is enough.
		if canWriteDir(filepath.Dir(dir)) || canCreateDir(dir) {
			return dest, nil
		}
	}
	return "", fmt.Errorf("no writable install dir (tried %s); use --prefix $HOME/.local or make install PREFIX=$$HOME/.local", strings.Join(candidates, ", "))
}

func defaultCLIBinDirs() []string {
	home, _ := os.UserHomeDir()
	var out []string
	if runtime.GOOS != "windows" {
		out = append(out, "/usr/local/bin")
	}
	if home != "" {
		out = append(out, filepath.Join(home, ".local", "bin"))
	}
	return out
}

func canWriteDir(dir string) bool {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	f, err := os.CreateTemp(dir, ".netra-write-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

func canCreateDir(dir string) bool {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	return canWriteDir(dir)
}

// installSelfCLI copies the running executable to dest.
func installSelfCLI(dest string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	src, err = filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dest + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("write %s: %w (try: make install PREFIX=$$HOME/.local)", dest, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// maybeInstallCLIAfterHelm installs netractl onto PATH after a successful
// cluster install/upgrade unless skipped.
func maybeInstallCLIAfterHelm(skip bool, prefix string) {
	if skip {
		return
	}
	dest, err := resolveCLIInstallPath(prefix, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: CLI not installed to PATH: %v\n", err)
		fmt.Fprintf(os.Stderr, "  fix: make install PREFIX=$$HOME/.local\n")
		return
	}
	if err := installSelfCLI(dest); err != nil {
		fmt.Fprintf(os.Stderr, "note: CLI not installed to PATH: %v\n", err)
		fmt.Fprintf(os.Stderr, "  fix: make install PREFIX=$$HOME/.local\n")
		return
	}
	fmt.Printf("CLI installed: %s\n", dest)
}
