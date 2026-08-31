package rule

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	M "github.com/sagernet/sing/common/metadata"
)

type zapretLookupCase struct {
	metadata adapter.InboundContext
	expected bool
}

func TestZapretProductionRuleSetsMatchAndStayBounded(t *testing.T) {
	domainPath, ipPath := zapretRuleSetPaths(t)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	domainRules := zapretLoadBinaryRules(t, domainPath)
	ipRules := zapretLoadBinaryRules(t, ipPath)
	loadDuration := time.Since(started)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	cases := zapretLookupCases()
	for index, testCase := range cases {
		actual := zapretMatch(domainRules, ipRules, testCase.metadata)
		if actual != testCase.expected {
			t.Fatalf("lookup case %d: expected %v, got %v", index, testCase.expected, actual)
		}
	}
	t.Logf(
		"ROUTING_CORE_LOAD domain_rules=%d ip_rules=%d load_us=%d total_alloc_bytes=%d",
		len(domainRules), len(ipRules), loadDuration.Microseconds(), allocated,
	)
	if loadDuration >= 2*time.Second {
		t.Fatalf("production rule-set load took %s", loadDuration)
	}
	if allocated >= 64<<20 {
		t.Fatalf("production rule-set load allocated %d bytes", allocated)
	}
}

func BenchmarkZapretProductionRuleSetLookup(b *testing.B) {
	domainPath, ipPath := zapretRuleSetPaths(b)
	domainRules := zapretLoadBinaryRules(b, domainPath)
	ipRules := zapretLoadBinaryRules(b, ipPath)
	cases := zapretLookupCases()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		testCase := cases[index%len(cases)]
		if zapretMatch(domainRules, ipRules, testCase.metadata) != testCase.expected {
			b.Fatal("unexpected production rule-set lookup result")
		}
	}
}

func zapretRuleSetPaths(tb testing.TB) (string, string) {
	tb.Helper()
	domainPath := os.Getenv("ZAPRET_RU_DOMAIN_SRS")
	ipPath := os.Getenv("ZAPRET_RU_IP_SRS")
	if domainPath == "" || ipPath == "" {
		tb.Fatal("production rule-set paths are missing")
	}
	return domainPath, ipPath
}

func zapretLoadBinaryRules(tb testing.TB, path string) []adapter.HeadlessRule {
	tb.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	compat, err := srs.Read(bytes.NewReader(content), false)
	if err != nil {
		tb.Fatal(err)
	}
	plain, err := compat.Upgrade()
	if err != nil {
		tb.Fatal(err)
	}
	rules := make([]adapter.HeadlessRule, len(plain.Rules))
	for index, ruleOptions := range plain.Rules {
		rules[index], err = NewHeadlessRule(context.Background(), ruleOptions)
		if err != nil {
			tb.Fatal(err)
		}
	}
	return rules
}

func zapretLookupCases() []zapretLookupCase {
	return []zapretLookupCase{
		{metadata: zapretDomainMetadata("example.ru"), expected: true},
		{metadata: zapretDomainMetadata("example.xn--p1ai"), expected: true},
		{metadata: zapretDomainMetadata("example.com"), expected: false},
		{metadata: zapretIPMetadata("5.255.255.5"), expected: true},
		{metadata: zapretIPMetadata("2a02:6b8::feed:0ff"), expected: true},
		{metadata: zapretIPMetadata("1.1.1.1"), expected: false},
		{metadata: zapretIPMetadata("2606:4700:4700::1111"), expected: false},
	}
}

func zapretDomainMetadata(domain string) adapter.InboundContext {
	return adapter.InboundContext{Domain: domain}
}

func zapretIPMetadata(address string) adapter.InboundContext {
	return adapter.InboundContext{Destination: M.SocksaddrFrom(M.ParseAddr(address), 443)}
}

func zapretMatch(
	domainRules []adapter.HeadlessRule,
	ipRules []adapter.HeadlessRule,
	metadata adapter.InboundContext,
) bool {
	for _, currentRule := range domainRules {
		current := metadata
		current.ResetRuleMatchCache()
		if currentRule.Match(&current) {
			return true
		}
	}
	for _, currentRule := range ipRules {
		current := metadata
		current.ResetRuleMatchCache()
		if currentRule.Match(&current) {
			return true
		}
	}
	return false
}
