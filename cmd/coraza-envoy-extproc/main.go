package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	envoy_service_extproc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/rikatz/coraza-envoy-extproc/pkg/waf"
	"google.golang.org/grpc"
)

var errorLogFile *os.File

func main() {
	port := flag.Int("port", 9001, "gRPC port")
	directivesFile := flag.String("directives", "./config/rules/default.conf", "WAF directive files")
	logfile := flag.String("logfile", "", "Path to write WAF error logs (for FTW testing)")
	flag.Parse()

	opts := &slog.HandlerOptions{}
	handler := slog.NewTextHandler(os.Stdout, opts)
	slog.SetDefault(slog.New(handler))

	if *logfile != "" {
		var err error
		errorLogFile, err = os.OpenFile(*logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fatal(fmt.Errorf("error opening log file %s: %w", *logfile, err))
		}
		defer func() { _ = errorLogFile.Close() }()
	}

	wafInstance, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithErrorCallback(logError).
		WithDirectivesFromFile(*directivesFile))
	if err != nil {
		fatal(fmt.Errorf("error loading coraza: %s", err))
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		fatal(fmt.Errorf("failed to listen to %d: %v", *port, err))
	}

	gs := grpc.NewServer()

	envoy_service_extproc_v3.RegisterExternalProcessorServer(gs, waf.NewExtProc(wafInstance))

	slog.Info("starting gRPC server", "port", *port)

	if err := gs.Serve(lis); err != nil {
		fatal(fmt.Errorf("gRPC server failed: %w", err))
	}
}

func logError(error types.MatchedRule) {
	msg := error.ErrorLog()
	slog.Info("[logError]", "severity", error.Rule().Severity(), "message", msg)
	if errorLogFile != nil {
		_, _ = fmt.Fprintln(errorLogFile, msg)
	}
}

func fatal(err error) {
	slog.Error("a fatal error has occured", "error", err)
	os.Exit(1)
}
