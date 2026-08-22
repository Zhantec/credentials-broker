// Package reqctx carries the hashed caller key across handler layers via
// request context, so every log line — not just the authz decision —
// can record caller+target+outcome per docs/spec.md.
package reqctx

import "context"

type callerKeyType struct{}

// WithCaller returns a context carrying the caller's hashed API key.
func WithCaller(ctx context.Context, callerHash string) context.Context {
	return context.WithValue(ctx, callerKeyType{}, callerHash)
}

// Caller returns the hashed caller key stored by WithCaller, or "" if none.
func Caller(ctx context.Context) string {
	v, _ := ctx.Value(callerKeyType{}).(string)
	return v
}
