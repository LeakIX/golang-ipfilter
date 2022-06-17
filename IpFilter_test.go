package filter

import "testing"

var testFilter *IpFilter

func TestNewIpFilter(t *testing.T) {
	var err error
	testFilter, err = NewIpFilter(
		WithRanges("129.0.0.0/8"))
	if err != nil {
		t.Error(err)
	}
	if testFilter == nil {
		t.Error("ipfilter should not be nil")
	}
}

func TestIpFilter_AddRanges(t *testing.T) {
	err := testFilter.AddRanges(PrivateRanges...)
	if err != nil {
		t.Error(err)
	}
}

func TestIpFilter_Allowed(t *testing.T) {
	allowed := testFilter.IsIpAllowed("8.8.8.8")
	if !allowed {
		t.Error("8.8.8.8 was not allowed")
	}
	allowed = testFilter.IsIpAllowed("2a00:1450:400e:80d::2004")
	if !allowed {
		t.Error("2a00:1450:400e:80d::2004 was not allowed")
	}
}

func TestIpFilter_Deny(t *testing.T) {
	allowed := testFilter.IsIpAllowed("192.168.77.1")
	if allowed {
		t.Error("192.168.77.1 was allowed")
	}
	allowed = testFilter.IsIpAllowed("129.1.1.1")
	if allowed {
		t.Error("129.1.1.1 was allowed (option)")
	}
	allowed = testFilter.IsIpAllowed("fe80::a855:34ff:fe7c:760d")
	if allowed {
		t.Error("fe80::a855:34ff:fe7c:760d/64 was allowed")
	}
}

func BenchmarkIpFilter_IsIpAllowed(b *testing.B) {
	var allowed bool
	for i := 0; i < b.N; i++ {
		allowed = testFilter.IsIpAllowed("240.0.0.3")
		if allowed {
			b.Error("240.0.0.3 was allowed during benchmark")
		}
	}
}
