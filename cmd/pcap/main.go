package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"

	"github.com/igolaizola/pcap"
	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"
)

// Build flags
var version = ""
var commit = ""
var date = ""

func main() {
	// Create signal based context
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Launch command
	cmd := newCommand()
	if err := cmd.ParseAndRun(ctx, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func newCommand() *ffcli.Command {
	fs := flag.NewFlagSet("pcap", flag.ExitOnError)

	return &ffcli.Command{
		ShortUsage: "pcap [flags] <subcommand>",
		FlagSet:    fs,
		Exec: func(context.Context, []string) error {
			return flag.ErrHelp
		},
		Subcommands: []*ffcli.Command{
			newVersionCommand(),
			newReqDurationCommand(),
		},
	}
}

func newVersionCommand() *ffcli.Command {
	return &ffcli.Command{
		Name:       "version",
		ShortUsage: "pcap version",
		ShortHelp:  "print version",
		Exec: func(ctx context.Context, args []string) error {
			v := version
			if v == "" {
				if buildInfo, ok := debug.ReadBuildInfo(); ok {
					v = buildInfo.Main.Version
				}
			}
			if v == "" {
				v = "dev"
			}
			versionFields := []string{v}
			if commit != "" {
				versionFields = append(versionFields, commit)
			}
			if date != "" {
				versionFields = append(versionFields, date)
			}
			fmt.Println(strings.Join(versionFields, " "))
			return nil
		},
	}
}

func newReqDurationCommand() *ffcli.Command {
	cmd := "req-duration"
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	_ = fs.String("config", "", "config file (optional)")
	file := fs.String("file", "", "pcap file")
	ip := fs.String("ip", "", "ip address")
	reqMin := fs.Int("req-min", 230, "request minimum length")
	reqMax := fs.Int("req-max", 235, "request maximum length")
	respMin := fs.Int("resp-min", 95, "response minimum length")
	respMax := fs.Int("resp-max", 100, "response maximum length")

	return &ffcli.Command{
		Name:       cmd,
		ShortUsage: fmt.Sprintf("pcap %s [flags] <key> <value data...>", cmd),
		Options: []ff.Option{
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(ff.PlainParser),
			ff.WithEnvVarPrefix("PCAP"),
		},
		ShortHelp: fmt.Sprintf("pcap %s command", cmd),
		FlagSet:   fs,
		Exec: func(ctx context.Context, args []string) error {
			if *file == "" {
				return fmt.Errorf("file is required")
			}
			if *ip == "" {
				return fmt.Errorf("ip is required")
			}
			return pcap.RequestDuration(ctx, *file, *ip, *reqMin, *reqMax, *respMin, *respMax)
		},
	}
}
