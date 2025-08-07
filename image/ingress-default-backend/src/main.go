package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/containerd/cgroups"
	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/rs/xid"
	"github.com/rs/zerolog"
	"go.elastic.co/ecszerolog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	CodeHeader        = "X-Code"
	ContentTypeHeader = "Content-Type"
	RequestIdHeader   = "X-Request-ID"
)

var ctxName string = fmt.Sprintf("%s.%s-%s", os.Getenv("NAMESPACE"), "ingress", xid.New().String())
var logger = ecszerolog.New(os.Stdout).With().Str("ctx", ctxName).Logger()

var (
	errorHandler *ErrorHandler
)

func handleError(w http.ResponseWriter, r *http.Request) {
	requestCount.WithLabelValues(r.Proto).Inc()

	errorHandler.HandleError(w, r)
}

func getEnv(key string, fallback ...string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	if len(fallback) > 0 {
		return fallback[0]
	}
	logger.Fatal().Msg(fmt.Sprintf("Environment variable %s is not set", key))
	return ""
}

func safeStringToInt(value string, defaultValue int) int {
	intValue, err := strconv.Atoi(value)
	if err != nil {
		logger.Warn().Msg(fmt.Sprintf("Invalid value '%s', defaulting to %d", value, defaultValue))
		return defaultValue
	}
	return intValue
}

func getBytes(goMemLimit string) int64 {
	if len(goMemLimit) < 2 {
		return 0
	}

	suffix := goMemLimit[len(goMemLimit)-2:]

	switch suffix {
	case "B":
		return int64(safeStringToInt(goMemLimit[:len(goMemLimit)-1], 0))
	case "KiB":
		fallthrough
	case "KB":
		return int64(safeStringToInt(goMemLimit[:len(goMemLimit)-2], 0) * 1024)
	case "MiB":
		fallthrough
	case "MB":
		return int64(safeStringToInt(goMemLimit[:len(goMemLimit)-2], 0) * 1024 * 1024)
	case "GiB":
		fallthrough
	case "GB":
		return int64(safeStringToInt(goMemLimit[:len(goMemLimit)-2], 0) * 1024 * 1024 * 1024)
	case "TiB":
		fallthrough
	case "TB":
		return int64(safeStringToInt(goMemLimit[:len(goMemLimit)-2], 0) * 1024 * 1024 * 1024 * 1024)
	default:
		return int64(safeStringToInt(goMemLimit, 0))
	}
}

func configGoGC() int64 {
	var memory uint64

	if cgroups.Mode() != cgroups.Unified {
		logger.Debug().Msg("V1 cgroups")
		control, err := cgroups.Load(cgroups.V1, cgroups.StaticPath("/"))

		if err == nil {
			logger.Debug().Msg("cgroup loaded")
			metrics, err := control.Stat(cgroups.IgnoreNotExist)

			if err == nil {
				memory = metrics.Memory.Usage.Limit
				logger.Info().Msgf("Available memory %d bytes", memory)
			} else {
				logger.Error().Err(err).Msg("Failed to stat cgroup")
			}
		}
	} else {
		logger.Info().Msg("V2 cgroups")
		control, err := cgroup2.Load("/")

		if err == nil {
			logger.Info().Msg("cgroup loaded")
			metrics, err := control.Stat()

			if err == nil {
				memory = metrics.Memory.UsageLimit
				logger.Info().Msgf("Available memory %d bytes", memory)
			} else {
				logger.Error().Err(err).Msg("Failed to stat cgroup")
			}
		}
	}

	osMemBytes := int64(safeStringToInt(getEnv("MEM_BYTES", "20000000"), 20000000)) // defaults to 20MB
	osMemEnv := os.Getenv("OSMEMBYTES")
	if osMemEnv != "" {
		value, err := strconv.ParseInt(osMemEnv, 10, 64)

		if err == nil {
			osMemBytes = value
		}
	}

	memLimit := os.Getenv("GOMEMLIMIT")
	if memLimit == "" && memory != 0 {
		limit := int64(memory) - osMemBytes
		logger.Info().Msgf("Setting memory limit automatically to %d bytes", limit)
		debug.SetMemoryLimit(limit) // subtract 10MB for system
		return limit
	}

	logger.Info().Msgf("Memory limit set to %s", memLimit)

	str := os.Getenv("GOGC")
	if str != "" {
		logger.Info().Msgf("GC percentage set to %s", str)
	}

	return getBytes(memLimit)
}

func main() {
	prometheus.MustRegister(requestCount)

	logLevel, err := zerolog.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil || logLevel == zerolog.NoLevel {
		logLevel = zerolog.ErrorLevel
	}
	zerolog.SetGlobalLevel(logLevel)

	defaultContentType := "text/html"
	pagesRoot := "/var/www"

	if contentType := os.Getenv("DEFAULT_CONTENT_TYPE"); contentType != "" {
		defaultContentType = contentType
	}

	if root := os.Getenv("PAGES_ROOT"); root != "" {
		pagesRoot = root
	}

	mem := configGoGC()

	cacheBytes := int64(0)

	if os.Getenv("CACHE_MEM_PERCENTAGE") != "" {
		cacheMemPercentage := safeStringToInt(os.Getenv("CACHE_MEM_PERCENTAGE"), 50)

		cacheBytes = int64(float64(mem) * float64(cacheMemPercentage) / 100)
	} else if os.Getenv("CACHE_MEM_BYTES") != "" {
		cacheBytes = getBytes(getEnv("CACHE_MEM_BYTES"))
	} else {
		logger.Warn().Msg("No cache memory limit set, defaulting to 50%% of available memory")
		cacheBytes = int64(float64(mem) * 0.5)
	}

	errorHandler = NewErrorHandler(defaultContentType, pagesRoot, NewFileReader(), cacheBytes)

	mux := http.NewServeMux()

	mux.HandleFunc("/", handleError)

	mux.Handle("/metrics", promhttp.Handler())

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       2 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

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
