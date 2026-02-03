package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"vibescan/internal/cve"
	"vibescan/internal/domain"
	"vibescan/internal/input"
	"vibescan/internal/render"
	"vibescan/internal/scan"
)

const (
	toolName        = "vibescan"
	oneLineDesc     = "Lightweight CLI scaffolding for authorized scan workflows."
	helpDisclaimer  = "Disclaimer: Use this tool only on systems you are authorized to scan."
	helpHintMessage = "Hint: use --help to see available commands."
)

// NewRootCmd builds the root command for the CLI.
func NewRootCmd() *cobra.Command {
	return NewRootCmdWithOptions(rootOptions{})
}

type rootOptions struct {
	scannerFactory func(options scanOptions) scan.Scanner
}

type scanOptions struct {
	ports     []int
	timeout   time.Duration
	recursive bool
}

// NewRootCmdWithOptions builds the root command with injectable dependencies.
func NewRootCmdWithOptions(options rootOptions) *cobra.Command {
	if options.scannerFactory == nil {
		options.scannerFactory = func(opts scanOptions) scan.Scanner {
			tcpScanner := scan.NewTCPScanner(opts.ports, opts.timeout, nil)
			client := cve.NewNVDClient(os.Getenv("NVD_API_KEY"), nil)
			cachedClient := cve.NewCachedClient(client)
			serviceScanner := scan.NewCVEEnricher(tcpScanner, cachedClient)
			return scan.NewWebScanner(serviceScanner, cachedClient, scan.WebOptions{
				Recursive: opts.recursive,
				Timeout:   opts.timeout,
			})
		}
	}

	var (
		portSpec     string
		fast         bool
		timeout      time.Duration
		nonRecursive bool
		inputPath    string
		format       string
	)

	cmd := &cobra.Command{
		Use:           toolName,
		Short:         oneLineDesc,
		Long:          fmt.Sprintf("%s\n\n%s", oneLineDesc, helpDisclaimer),
		SilenceUsage:  true,
		SilenceErrors: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if inputPath != "" {
				if len(args) > 0 {
					return fmt.Errorf("no positional targets allowed with --input")
				}
				return nil
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				result domain.ScanResult
				err    error
			)

			if inputPath != "" {
				result, err = input.ParseNmapFile(inputPath)
				if err != nil {
					return err
				}
				if result.Tool == "" {
					result.Tool = toolName
				}
			} else {
				targets, err := input.ParseTargets(args[0])
				if err != nil {
					return err
				}

				ports, err := input.ParsePorts(portSpec)
				if err != nil {
					return err
				}

				if fast && !cmd.Flags().Changed("timeout") {
					timeout = 200 * time.Millisecond
				}

				scanTargets := make([]domain.Target, 0, len(targets))
				for _, target := range targets {
					scanTargets = append(scanTargets, domain.Target{Address: target})
				}

				result = domain.ScanResult{Tool: toolName, Targets: scanTargets}
				manager := scan.ScanManager{Scanner: options.scannerFactory(scanOptions{
					ports:     ports,
					timeout:   timeout,
					recursive: !nonRecursive,
				})}
				result, _ = manager.Run(cmd.Context(), result)
			}

			output, err := renderOutput(format, result)
			if err != nil {
				return err
			}

			if isPlainFormat(format) {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n%s\n%s\n\n", toolName, oneLineDesc, helpHintMessage)
				if err != nil {
					return err
				}
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), output)
			return err
		},
	}

	cmd.Flags().StringVarP(&portSpec, "ports", "p", "80,443", "Ports to scan (comma-separated or ranges)")
	cmd.Flags().BoolVar(&fast, "fast", false, "Use a shorter timeout")
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Second, "Per-port timeout")
	cmd.Flags().BoolVar(&nonRecursive, "non-recursive", false, "Disable recursive web scanning")
	cmd.Flags().StringVarP(&inputPath, "input", "i", "", "Load targets from Nmap XML (bypasses scanning)")
	cmd.Flags().StringVar(&format, "format", "plain", "Output format: plain, json, xml")

	return cmd
}

// Execute runs the root command.
func Execute() error {
	return NewRootCmd().Execute()
}

func renderOutput(format string, result domain.ScanResult) (string, error) {
	switch normalizeFormat(format) {
	case "plain":
		return render.RenderPlain(result), nil
	case "json":
		return render.RenderJSON(result)
	case "xml":
		return render.RenderXML(result)
	default:
		return "", fmt.Errorf("unsupported format %q", format)
	}
}

func normalizeFormat(format string) string {
	value := strings.ToLower(strings.TrimSpace(format))
	if value == "" {
		return "plain"
	}
	return value
}

func isPlainFormat(format string) bool {
	return normalizeFormat(format) == "plain"
}
