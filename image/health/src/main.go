package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"go.elastic.co/ecszerolog"
)

var ctxName string = fmt.Sprintf("%s.%s-%s", os.Getenv("NAMESPACE"), "health", xid.New().String())
var logger = ecszerolog.New(os.Stdout).With().Str("ctx", ctxName).Logger()

// ping is a simple ping check handler. If the server is up, it will return a 204 status code.
func ping(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// healthCheck is a health check handler. If the server is up, it will return a 200 status code.
// In the future we will use this to check the health of the services by invoking the service's health check endpoint or similar.
func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	logLevel, err := zerolog.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil || logLevel == zerolog.NoLevel {
		logLevel = zerolog.ErrorLevel // default to ERROR
	}
	zerolog.SetGlobalLevel(logLevel)

	server := &http.Server{
		Addr:              ":8080",
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       2 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	http.HandleFunc("/v1/ping", ping)
	http.HandleFunc("/v1/check", healthCheck)

	go func() {
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal().Err(err).Msg("Failed to start server")
		}
		logger.Info().Msg("Server stopped")
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error().Err(err).Msg("Failed to shutdown server")
		server.Close()
	}

	logger.Info().Msg("Server shutdown")

}
