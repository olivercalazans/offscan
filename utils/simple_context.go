package utils

import (
	"context"
	"os/signal"
	"syscall"
)



func SignalContext() context.Context {
    ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    return ctx
}