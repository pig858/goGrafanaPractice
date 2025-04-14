package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"

	"github.com/gin-gonic/gin"
)

type ctxKeyLogger struct{}

var (
	requestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "app_http_requests_total",
			Help: "總請求數",
		},
		[]string{"method", "path"},
	)

	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "app_http_request_duration_seconds",
			Help:    "每個 API 的請求延遲時間",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
)

func initTracer() {
	ctx := context.Background()
	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint("otel-collector:4318"),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		panic(err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("demo-app"),
		)),
	)
	otel.SetTracerProvider(tp)
}

func traceAndLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, span := otel.Tracer("demo-app").Start(c, "incoming request")
		defer span.End()

		traceID := span.SpanContext().TraceID().String()
		logger := slog.Default().With("trace_id", traceID)
		ctx = context.WithValue(ctx, ctxKeyLogger{}, logger)
	}
}

func metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		timer := prometheus.NewTimer(requestDuration.WithLabelValues(c.Request.Method, c.Request.URL.Path))
		defer timer.ObserveDuration()

		requestCounter.WithLabelValues(c.Request.Method, c.Request.URL.Path).Inc()
	}
}

func loggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKeyLogger{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

func hello(c *gin.Context) {
	time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)
	c.String(http.StatusOK, "hello")
}

func cpu(c *gin.Context) {
	x := 0
	for i := 0; i < 1e7; i++ {
		x += i
	}

	c.String(http.StatusOK, fmt.Sprintf("CPU done: %d\n", x))
}

func metrics(c *gin.Context) {
	promhttp.Handler().ServeHTTP(c.Writer, c.Request)
}

func handler(w http.ResponseWriter, r *http.Request) {
	logger := loggerFromContext(r.Context())
	logger.Info("handling request")
	time.Sleep(200 * time.Millisecond)
	fmt.Fprintln(w, "Hello trace + log!")
}

func main() {
	prometheus.MustRegister(requestCounter)
	prometheus.MustRegister(requestDuration)
	initTracer()
	f, _ := os.OpenFile("/var/log/app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	logger := slog.New(slog.NewJSONHandler(f, nil))
	slog.SetDefault(logger)

	r := gin.Default()
	r.Use(traceAndLogMiddleware(), metricsMiddleware())
	r.GET("/metrics", metrics)
	r.GET("/hello", hello)
	r.GET("/cpu", cpu)

	slog.Info("Starting server on :8080")
	r.Run(":8080")
}
