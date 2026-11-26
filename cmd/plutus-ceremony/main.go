/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

// plutus-ceremony is the CLI tool used to perform the Plutus trust-chain
// ceremony: generating the Offline Root key, certifying Platform Keys,
// signing PRC deployment certificates, and rotating keys. Each command
// wraps a function in the maintainer package and performs the same
// cryptographic operations the library provides — the CLI only handles
// I/O (file paths, passphrase prompting, terminal output).
//
// Typical flow (air-gapped laptop):
//
//	plutus-ceremony generate-root                 # creates root.json
//	plutus-ceremony sign-platform --root root.json  # creates platform.cert + platform.key
//
// Typical flow (online signer host):
//
//	plutus-ceremony certify-prc polygon --platform platform.key --addr 0x... --tx 0x... --block 12345
//	plutus-ceremony emit-canonical --root root.json --platform-cert platform.cert --deploy-certs polygon.cert,base.cert
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// subcommand describes one of the top-level plutus-ceremony verbs.
type subcommand struct {
	name string
	desc string
	run  func(args []string) error
}

var subcommands = []subcommand{
	{name: "generate-root", desc: "Generate Offline Root keypair (requires passphrase)", run: runGenerateRoot},
	{name: "sign-platform", desc: "Sign a Platform Key certificate with the Offline Root", run: runSignPlatform},
	{name: "certify-prc", desc: "Sign a PRC deployment certificate per chain", run: runCertifyPRC},
	{name: "rotate-platform", desc: "Rotate the Platform Key and emit a new certificate", run: runRotatePlatform},
	{name: "verify", desc: "Verify a key or certificate file", run: runVerify},
	{name: "emit-canonical", desc: "Print the canonical/embed.go snippet from ceremony artifacts", run: runEmitCanonical},
}

func main() {
	if len(os.Args) < 2 {
		printTopLevelUsage(os.Stderr)
		os.Exit(2)
	}

	verb := os.Args[1]
	if verb == "-h" || verb == "--help" || verb == "help" {
		printTopLevelUsage(os.Stdout)
		return
	}

	for _, sc := range subcommands {
		if sc.name == verb {
			if err := sc.run(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "plutus-ceremony %s: %v\n", sc.name, err)
				os.Exit(1)
			}
			return
		}
	}

	fmt.Fprintf(os.Stderr, "plutus-ceremony: unknown command %q\n\n", verb)
	printTopLevelUsage(os.Stderr)
	os.Exit(2)
}

// printTopLevelUsage prints the top-level help message.
func printTopLevelUsage(w *os.File) {
	var b strings.Builder
	b.WriteString("plutus-ceremony — Plutus trust-chain key ceremony tool\n\n")
	b.WriteString("Usage: plutus-ceremony <command> [flags]\n\n")
	b.WriteString("Commands:\n")
	for _, sc := range subcommands {
		fmt.Fprintf(&b, "  %-16s %s\n", sc.name, sc.desc)
	}
	b.WriteString("\nRun 'plutus-ceremony <command> --help' for per-command flags.\n")
	writeUsage(w, b.String())
}

// writeUsage writes a usage text to w. A usage text the terminal cannot take
// has nowhere else to go, so the write error is not kept.
func writeUsage(w io.Writer, text string) {
	_, _ = io.WriteString(w, text)
}

// newFlagSet returns a flag.FlagSet that writes usage errors to stderr and
// exits on parse failures. It also attaches a brief help header.
func newFlagSet(name, desc string) *flag.FlagSet {
	fs := flag.NewFlagSet("plutus-ceremony "+name, flag.ExitOnError)
	fs.Usage = func() {
		writeUsage(fs.Output(), fmt.Sprintf("%s — %s\n\nUsage: %s [flags]\n\nFlags:\n", fs.Name(), desc, fs.Name()))
		fs.PrintDefaults()
	}
	return fs
}
