package main

import (
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	envoy_service_extproc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/fsnotify/fsnotify"
	"github.com/rikatz/coraza-envoy-extproc/pkg/waf"
	"google.golang.org/grpc"
)

var errorLogFile *os.File

func main() {
	port := flag.Int("port", 9001, "gRPC port")
	directivesFile := flag.String("directives", "./config/rules/default.conf", "WAF directive files")
	logfile := flag.String("logfile", "", "Path to write WAF error logs (for FTW testing)")
	flag.Parse()
	absPath, err := filepath.Abs(*directivesFile)
	if err != nil {
		fatal(err)
	}

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

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fatal(err)
	}
	defer func() { _ = watcher.Close() }()

	wafInstance, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithErrorCallback(logError).
		WithDirectivesFromFile(absPath))
	if err != nil {
		fatal(fmt.Errorf("error loading coraza: %s", err))
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		fatal(fmt.Errorf("failed to listen to %d: %v", *port, err))
	}

	gs := grpc.NewServer()

	wafSvc := waf.NewExtProc(wafInstance)
	envoy_service_extproc_v3.RegisterExternalProcessorServer(gs, wafSvc)

	slog.Info("starting gRPC server", "port", *port)

	/*
		Usually file change operations are batched (eg.: you do not change
		just one file.)
		This way, we put a delay of 500ms to give the WAF opportunity to receive all
		of the changes before applying the new rules
	*/
	const delay = 50 * time.Millisecond
	timer := time.NewTimer(delay)
	if !timer.Stop() {
		<-timer.C
	}
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				log.Println("event:", event)
				// If a timer is already running, reset it
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(delay)

				log.Println("finished processing files")
			case <-timer.C:
				newWafInstance, err := coraza.NewWAF(coraza.NewWAFConfig().
					WithErrorCallback(logError).
					WithDirectivesFromFile(absPath))
				if err != nil {
					log.Printf("error loading new rules, will not reload: %s", err)
					continue
				}
				if err := wafSvc.UpdateWAF(newWafInstance); err != nil {
					log.Printf("error loading instance, will not reload: %s", err)
					continue
				}
				log.Println("=== WAF reloaded ===")
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)

			}
		}
	}()

	rootDir := filepath.Dir(absPath)
	err = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return watcher.Add(path)
		}
		return nil
	})
	if err != nil {
		fatal(err)
	}

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
