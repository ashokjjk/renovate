package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "default_http_backend"
	subsystem = "http"
)

var (
	requestCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: subsystem,
		Name:      "request_count_total",
		Help:      "Counter of HTTP requests.",
	}, []string{"proto"})
)
