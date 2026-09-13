package util

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/sirupsen/logrus"
)

func StartRoutine(ctx context.Context, d time.Duration, f func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorln("[BUG]", r, string(debug.Stack()))
			}
		}()
		for {
			time.Sleep(d)
			f()
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
}
