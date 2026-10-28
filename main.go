package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sub2sfm/pkg/server"
)

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func main() {
	host := flag.String("host", getEnv("HOST", "0.0.0.0"), "HTTP 监听主机地址 (亦可通过 HOST 环境变量设置)")
	port := flag.String("port", getEnv("PORT", "8088"), "HTTP 监听端口 (亦可通过 PORT 环境变量设置)")
	flag.Parse()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	h := server.NewHandler(logger)
	addr := fmt.Sprintf("%s:%s", *host, *port)

	srv := &http.Server{
		Addr:         addr,
		Handler:      h.Router(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// 启动后台 HTTP 服务
	go func() {
		logger.Info("sub2sfm 订阅转换服务已启动", "address", fmt.Sprintf("http://%s", addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("服务异常退出", "error", err)
			os.Exit(1)
		}
	}()

	// 监听中断信号优雅关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.Info("正在优雅关闭服务...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("服务关闭失败", "error", err)
	} else {
		logger.Info("服务已停止")
	}
}
