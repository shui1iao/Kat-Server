package kernel

import "testing"

func BenchmarkDNSNameNormalized(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s, err := dnsName("sub.api.example.com")
		if err != nil || s != "sub.api.example.com" {
			b.Fatalf("got (%q, %v)", s, err)
		}
	}
}
