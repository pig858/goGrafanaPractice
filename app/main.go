package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

/* ---------- (1) 自訂 slog.Handler：自動注入 service_name + trace_id ---------- */

type svcHandler struct {
	slog.Handler
	svc string
}

func (h svcHandler) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(slog.String("service_name", h.svc))
	if span := trace.SpanFromContext(ctx); span != nil {
		if sc := span.SpanContext(); sc.IsValid() {
			r.AddAttrs(slog.String("trace_id", sc.TraceID().String()))
		}
	}
	return h.Handler.Handle(ctx, r)
}

func newLogger() *slog.Logger {
	h := svcHandler{
		Handler: slog.NewJSONHandler(os.Stdout, nil),
		svc:     "demo-app",
	}
	return slog.New(h)
}

/* ------------------------- (2) Prometheus metrics ---------------------------- */

var (
	requestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "app_http_requests_total",
			Help: "HTTP 請求總數",
		},
		[]string{"method", "path"},
	)
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "app_http_request_duration_seconds",
			Help:    "HTTP 請求延遲",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
)

/* -------------------- (3) OpenTelemetry TracerProvider ----------------------- */

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

/* ------------------------ (4) Gin middlewares -------------------------------- */

type ctxKeyLogger struct{}

func traceAndLogMiddleware(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, span := otel.Tracer("demo-app").Start(c.Request.Context(), "incoming request")
		defer span.End()

		ctx = context.WithValue(ctx, ctxKeyLogger{}, logger)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

func metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		timer := prometheus.NewTimer(
			requestDuration.WithLabelValues(c.Request.Method, c.FullPath()),
		)
		defer timer.ObserveDuration()
		requestCounter.WithLabelValues(c.Request.Method, c.FullPath()).Inc()
		c.Next()
	}
}

/* ---------- (★ 新增) access‑log middleware：每請求寫一筆 slog --------------- */

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		ctx := c.Request.Context()
		l := loggerFromContext(ctx)

		l.InfoContext(ctx, "request",
			"method", c.Request.Method,
			"path", c.FullPath(),
			"status", c.Writer.Status(),
			"latency_ms", time.Since(start).Milliseconds(),
			"client_ip", c.ClientIP(),
		)
	}
}

/* ---------------------- (5) Helper 取 logger from ctx ----------------------- */

func loggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKeyLogger{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

/* --------------------------- (6) Handlers ----------------------------------- */

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

/* ------------------------------ (7) main ------------------------------------ */

func main() {
	prometheus.MustRegister(requestCounter, requestDuration)
	initTracer()

	logger := newLogger()
	slog.SetDefault(logger)

	gin.SetMode(gin.ReleaseMode)
	gin.DefaultWriter = io.Discard // 關掉內建 access‑log

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(traceAndLogMiddleware(logger), metricsMiddleware(), requestLogger())

	r.GET("/metrics", metrics)
	r.GET("/hello", hello)
	r.GET("/cpu", cpu)

	logger.Info("starting server", "port", 8080)
	if err := r.Run(":8080"); err != nil {
		logger.Error("server stopped", "err", err)
	}
}
