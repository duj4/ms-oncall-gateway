package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/duj4/ms-oncall-gateway/internal/httpapi"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	address := os.Getenv("MS_ONCALL_GATEWAY_LISTEN_ADDR")
	if address == "" {
		address = httpapi.DefaultListenAddress
	}

	handler := httpapi.NewHandler(httpapi.UnavailableSink{}, logger)
	server := httpapi.NewServer(address, handler)
	shutdownSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverError := make(chan error, 1)
	go func() {
		logger.Info("server_starting")
		serverError <- server.ListenAndServe()
	}()

	select {
	case err := <-serverError:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server_failed")
			os.Exit(1)
		}
	case <-shutdownSignal.Done():
		logger.Info("server_stopping")
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			logger.Error("server_shutdown_failed")
			os.Exit(1)
		}
		if err := <-serverError; !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server_failed")
			os.Exit(1)
		}
	}
}
