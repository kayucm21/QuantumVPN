package fallback

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
)

// This file is copied into the exact pinned checkout only for `go test` and is
// removed immediately afterwards. It deliberately tests the unexported
// strategy implementation without patching the libbox binary we ship.
type zapretAuditTransport struct {
	tag      string
	calls    int
	exchange func(context.Context, *dns.Msg) (*dns.Msg, error)
}

func (t *zapretAuditTransport) Start(adapter.StartStage) error { return nil }
func (t *zapretAuditTransport) Close() error                   { return nil }
func (t *zapretAuditTransport) Type() string                   { return "audit" }
func (t *zapretAuditTransport) Tag() string                    { return t.tag }
func (t *zapretAuditTransport) Dependencies() []string         { return nil }
func (t *zapretAuditTransport) Reset()                         {}
func (t *zapretAuditTransport) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	t.calls++
	return t.exchange(ctx, message)
}

type zapretCtxKey struct{}

type zapretNopLogger struct{}

func (zapretNopLogger) Trace(args ...any)                                 {}
func (zapretNopLogger) Debug(args ...any)                                 {}
func (zapretNopLogger) Info(args ...any)                                  {}
func (zapretNopLogger) Notice(args ...any)                                {}
func (zapretNopLogger) Warn(args ...any)                                  {}
func (zapretNopLogger) Error(args ...any)                                 {}
func (zapretNopLogger) Fatal(args ...any)                                 {}
func (zapretNopLogger) Panic(args ...any)                                 {}
func (zapretNopLogger) TraceContext(context.Context, ...any)              {}
func (zapretNopLogger) DebugContext(context.Context, ...any)              {}
func (zapretNopLogger) InfoContext(context.Context, ...any)               {}
func (zapretNopLogger) NoticeContext(context.Context, ...any)             {}
func (zapretNopLogger) WarnContext(context.Context, ...any)               {}
func (zapretNopLogger) ErrorContext(context.Context, ...any)              {}
func (zapretNopLogger) FatalContext(context.Context, ...any)              {}
func (zapretNopLogger) PanicContext(context.Context, ...any)              {}
func (zapretNopLogger) TraceContextLevel(context.Context, int, ...any)    {}
func (zapretNopLogger) DebugContextLevel(context.Context, int, ...any)    {}
func (l zapretNopLogger) WithContext(context.Context) logger.ContextLogger {
	return l
}

func zapretCreate(t *testing.T, strategy string, servers []adapter.DNSTransport) ExchangeStrategy {
	t.Helper()
	created, err := CreateStrategy(strategy, servers, zapretNopLogger{}, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func TestZapretSequentialSuccessStopsAtFirstTransportAndKeepsContext(t *testing.T) {
	shared := context.WithValue(context.Background(), zapretCtxKey{}, "shared")
	query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	want := new(dns.Msg).SetReply(query)
	first := &zapretAuditTransport{tag: "first"}
	first.exchange = func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
		if ctx.Value(zapretCtxKey{}) != "shared" {
			t.Fatal("first transport lost parent context values")
		}
		return want, nil
	}
	second := &zapretAuditTransport{tag: "second"}
	second.exchange = func(context.Context, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("second transport ran after first success")
		return nil, nil
	}

	response, err := zapretCreate(t, "sequential", []adapter.DNSTransport{first, second})(shared, query)
	if err != nil || response != want {
		t.Fatalf("unexpected result: response=%p error=%v", response, err)
	}
	if first.calls != 1 || second.calls != 0 {
		t.Fatalf("unexpected call counts: first=%d second=%d", first.calls, second.calls)
	}
}

func TestZapretSequentialTransportErrorFallsBackWithSameContext(t *testing.T) {
	shared := context.WithValue(context.Background(), zapretCtxKey{}, "shared")
	query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	want := new(dns.Msg).SetReply(query)
	first := &zapretAuditTransport{tag: "first"}
	first.exchange = func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
		if ctx.Value(zapretCtxKey{}) != "shared" {
			t.Fatal("first transport lost parent context values")
		}
		return nil, errors.New("transport failed")
	}
	second := &zapretAuditTransport{tag: "second"}
	second.exchange = func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
		if ctx.Value(zapretCtxKey{}) != "shared" {
			t.Fatal("fallback transport lost parent context values")
		}
		return want, nil
	}

	response, err := zapretCreate(t, "", []adapter.DNSTransport{first, second})(shared, query)
	if err != nil || response != want {
		t.Fatalf("unexpected result: response=%p error=%v", response, err)
	}
	if first.calls != 1 || second.calls != 1 {
		t.Fatalf("unexpected call counts: first=%d second=%d", first.calls, second.calls)
	}
}

func TestZapretSequentialHangConsumesSharedDeadline(t *testing.T) {
	shared, cancel := context.WithTimeout(context.WithValue(context.Background(), zapretCtxKey{}, "shared"), 40*time.Millisecond)
	defer cancel()
	query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	first := &zapretAuditTransport{tag: "first"}
	first.exchange = func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
		if ctx.Value(zapretCtxKey{}) != "shared" {
			t.Fatal("first transport lost parent context values")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	second := &zapretAuditTransport{tag: "second"}
	second.exchange = func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
		if ctx.Value(zapretCtxKey{}) != "shared" {
			t.Fatal("fallback transport lost parent context values")
		}
		if ctx.Err() == nil {
			<-ctx.Done()
		}
		return nil, ctx.Err()
	}

	response, err := zapretCreate(t, "sequential", []adapter.DNSTransport{first, second})(shared, query)
	if response != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected result: response=%p error=%v", response, err)
	}
	if first.calls != 1 || second.calls != 1 {
		t.Fatalf("unexpected call counts: first=%d second=%d", first.calls, second.calls)
	}
}

func TestZapretSequentialNxdomainIsAResultNotFallback(t *testing.T) {
	shared := context.WithValue(context.Background(), zapretCtxKey{}, "nx")
	query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	want := new(dns.Msg).SetReply(query)
	want.Rcode = dns.RcodeNameError
	first := &zapretAuditTransport{tag: "first"}
	first.exchange = func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
		if ctx.Value(zapretCtxKey{}) != "nx" {
			t.Fatal("first transport lost parent context values")
		}
		return want, nil
	}
	second := &zapretAuditTransport{tag: "second"}
	second.exchange = func(context.Context, *dns.Msg) (*dns.Msg, error) {
		t.Fatal("second transport ran after NXDOMAIN")
		return nil, nil
	}

	response, err := zapretCreate(t, "sequential", []adapter.DNSTransport{first, second})(shared, query)
	if err != nil || response == nil || response.Rcode != dns.RcodeNameError {
		t.Fatalf("unexpected result: response=%v error=%v", response, err)
	}
	if first.calls != 1 || second.calls != 0 {
		t.Fatalf("unexpected call counts: first=%d second=%d", first.calls, second.calls)
	}
}

func TestZapretSequentialServfailFallsBack(t *testing.T) {
	shared := context.WithValue(context.Background(), zapretCtxKey{}, "servfail")
	query := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	bad := new(dns.Msg).SetReply(query)
	bad.Rcode = dns.RcodeServerFailure
	want := new(dns.Msg).SetReply(query)
	first := &zapretAuditTransport{tag: "first"}
	first.exchange = func(context.Context, *dns.Msg) (*dns.Msg, error) {
		return bad, nil
	}
	second := &zapretAuditTransport{tag: "second"}
	second.exchange = func(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
		if ctx.Value(zapretCtxKey{}) != "servfail" {
			t.Fatal("fallback transport lost parent context values")
		}
		return want, nil
	}

	response, err := zapretCreate(t, "sequential", []adapter.DNSTransport{first, second})(shared, query)
	if err != nil || response != want {
		t.Fatalf("unexpected result: response=%p error=%v", response, err)
	}
	if first.calls != 1 || second.calls != 1 {
		t.Fatalf("unexpected call counts: first=%d second=%d", first.calls, second.calls)
	}
}
