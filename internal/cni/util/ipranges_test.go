package util_test

import (
	"code.cloudfoundry.org/k8s-policy-agent/internal/cni/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RangeToCIDRs", func() {

	DescribeTable("IP ranges", func(ipRange string, expectedCIDRs []string) {
		ranges, err := util.RangeToCIDRs(ipRange)
		Expect(err).NotTo(HaveOccurred())
		Expect(ranges).To(ConsistOf(expectedCIDRs))
	},
		Entry("small range within a /24", "10.0.0.0-10.0.0.7", []string{"10.0.0.0/29"}),
		Entry("complex range", "192.168.1.0-192.168.1.10", []string{
			"192.168.1.0/29",
			"192.168.1.8/31",
			"192.168.1.10/32",
		}),
		Entry("large range", "169.255.0.0-172.15.255.255", []string{
			"169.255.0.0/16",
			"170.0.0.0/7",
			"172.0.0.0/12",
		}),
		Entry("range that stops ", "255.255.255.250-255.255.255.255", []string{
			"255.255.255.250/31",
			"255.255.255.252/30",
		}),
		Entry("maximal range", "0.0.0.0-255.255.255.255", []string{
			"0.0.0.0/0",
		}),
		Entry("single ip range #1", "255.255.255.255-255.255.255.255", []string{
			"255.255.255.255/32",
		}),
		Entry("single ip range #2", "0.0.0.0-0.0.0.0", []string{
			"0.0.0.0/32",
		}),
		Entry("single ip range #3", "10.0.0.5-10.0.0.5", []string{
			"10.0.0.5/32",
		}),
	)

	DescribeTable("invalid IP ranges", func(ipRange string) {
		_, err := util.RangeToCIDRs(ipRange)
		Expect(err).To(HaveOccurred())
	},
		Entry("invalid IP addresses", "10.0.0.256-10.0.0.257"),
		Entry("reversed range", "10.0.0.10-10.0.0.5"),
		Entry("missing range separator", "10.0.0.1"),
	)
})
