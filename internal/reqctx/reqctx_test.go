package reqctx

import (
	"context"
	"testing"
)

func TestWithCallerAndCaller(t *testing.T) {
	ctx := WithCaller(context.Background(), "abc123")
	if got := Caller(ctx); got != "abc123" {
		t.Errorf("Caller = %q, want %q", got, "abc123")
	}
}

func TestCaller_NotSet(t *testing.T) {
	if got := Caller(context.Background()); got != "" {
		t.Errorf("Caller = %q, want empty string", got)
	}
}
