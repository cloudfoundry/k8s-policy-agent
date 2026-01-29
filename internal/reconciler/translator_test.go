package reconciler_test

import (
	policy "code.cloudfoundry.org/policy_client"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
	"k8s.io/apimachinery/pkg/util/intstr"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"code.cloudfoundry.org/k8s-policy-agent/internal/reconciler"
)

var _ = Describe("Translator", func() {
	Describe("CreateCiliumEgressRulesFromASG", func() {
		It("creates egress rules for valid ASG rules with TCP ports", func() {
			asgRules := []policy.SecurityGroupRule{
				{
					Destination: "10.0.0.1",
					Protocol:    "tcp",
					Ports:       "80,443",
				},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(HaveLen(1))
			Expect(rules[0].ToCIDR).To(ConsistOf(ciliumapi.CIDR("10.0.0.1/32")))
			Expect(rules[0].ToPorts).To(HaveLen(2))
			Expect(rules[0].ToPorts[0].Ports[0].Port).To(Equal("80"))
			Expect(rules[0].ToPorts[0].Ports[0].Protocol).To(Equal(ciliumapi.ProtoTCP))
			Expect(rules[0].ToPorts[1].Ports[0].Port).To(Equal("443"))
		})

		It("creates egress rule for ICMP protocol without ports", func() {
			asgRules := []policy.SecurityGroupRule{
				{Destination: "10.0.0.8", Protocol: "icmp", Type: 8},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(HaveLen(1))
			Expect(rules[0].ToCIDR).To(ConsistOf(ciliumapi.CIDR("10.0.0.8/32")))
			Expect(rules[0].ToPorts).To(BeEmpty())
			Expect(rules[0].ICMPs).To(ConsistOf(ciliumapi.ICMPRule{
				Fields: []ciliumapi.ICMPField{{
					Family: ciliumapi.IPv4Family,
					Type: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8,
					},
				}},
			}))
		})

		It("creates egress rule for ICMP protocol with all types", func() {
			asgRules := []policy.SecurityGroupRule{
				{Destination: "10.0.0.8", Protocol: "icmp", Type: -1},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(HaveLen(1))
			Expect(rules[0].ToCIDR).To(ConsistOf(ciliumapi.CIDR("10.0.0.8/32")))
			Expect(rules[0].ToPorts).To(BeEmpty())
			for _, icmpType := range reconciler.GetIcmpTypes(ciliumapi.IPv4Family) {
				Expect(rules[0].ICMPs[0].Fields).To(ContainElement(
					ciliumapi.ICMPField{
						Family: ciliumapi.IPv4Family,
						Type: &intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: int32(icmpType),
						},
					},
				))
			}
		})

		It("creates egress rule for ICMPv6 protocol without ports", func() {
			asgRules := []policy.SecurityGroupRule{
				{Destination: "10.0.0.8", Protocol: "icmpv6", Type: 8},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(HaveLen(1))
			Expect(rules[0].ToCIDR).To(ConsistOf(ciliumapi.CIDR("10.0.0.8/32")))
			Expect(rules[0].ToPorts).To(BeEmpty())
			Expect(rules[0].ICMPs).To(ConsistOf(ciliumapi.ICMPRule{
				Fields: []ciliumapi.ICMPField{{
					Family: ciliumapi.IPv6Family,
					Type: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8,
					},
				}},
			}))
		})

		It("creates egress rule for ICMPv6 protocol with all types", func() {
			asgRules := []policy.SecurityGroupRule{
				{Destination: "10.0.0.8", Protocol: "icmpv6", Type: -1},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(HaveLen(1))
			Expect(rules[0].ToCIDR).To(ConsistOf(ciliumapi.CIDR("10.0.0.8/32")))
			Expect(rules[0].ToPorts).To(BeEmpty())
			for _, icmpType := range reconciler.GetIcmpTypes(ciliumapi.IPv6Family) {
				Expect(rules[0].ICMPs[0].Fields).To(ContainElement(
					ciliumapi.ICMPField{
						Family: ciliumapi.IPv6Family,
						Type: &intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: int32(icmpType),
						},
					},
				))
			}
		})

		It("creates egress rules for UDP protocol", func() {
			asgRules := []policy.SecurityGroupRule{
				{
					Destination: "10.0.0.2/24",
					Protocol:    "udp",
					Ports:       "53",
				},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(HaveLen(1))
			Expect(rules[0].ToCIDR).To(ConsistOf(ciliumapi.CIDR("10.0.0.2/24")))
			Expect(rules[0].ToPorts[0].Ports[0].Protocol).To(Equal(ciliumapi.ProtoUDP))
		})

		It("does set only cidrs for ALL protocol", func() {
			asgRules := []policy.SecurityGroupRule{
				{
					Destination: "10.0.0.9/24",
					Protocol:    "all",
				},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules[0].ToCIDR).To(ConsistOf(ciliumapi.CIDR("10.0.0.9/24")))
		})

		It("does not create rules for unknown protocol", func() {
			asgRules := []policy.SecurityGroupRule{
				{
					Destination: "10.0.0.3",
					Protocol:    "foo",
					Ports:       "1234",
				},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(HaveLen(0))
		})

		It("ignores rules with invalid destination", func() {
			asgRules := []policy.SecurityGroupRule{
				{
					Destination: "",
					Protocol:    "tcp",
					Ports:       "80",
				},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(BeEmpty())
		})

		It("creates rule without ports if Ports is empty", func() {
			asgRules := []policy.SecurityGroupRule{
				{
					Destination: "10.0.0.4",
					Protocol:    "tcp",
					Ports:       "",
				},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(HaveLen(1))
			Expect(rules[0].ToPorts).To(ConsistOf(ciliumapi.PortRule{
				Ports: []ciliumapi.PortProtocol{{
					Port:     "1",
					EndPort:  65535,
					Protocol: ciliumapi.ProtoTCP,
				}},
			}))
		})

		It("trims whitespace around ports", func() {
			asgRules := []policy.SecurityGroupRule{
				{Destination: "10.0.0.9", Protocol: "tcp", Ports: " 81 ,  82"},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules[0].ToPorts[0].Ports[0].Port).To(Equal("81"))
			Expect(rules[0].ToPorts[1].Ports[0].Port).To(Equal("82"))
		})

		It("translates comma-delimited destinations", func() {
			asgRules := []policy.SecurityGroupRule{
				{
					Destination: "10.0.0.0,10.0.1.0/24,10.0.2.0-10.0.2.127",
					Protocol:    "tcp",
					Ports:       "80",
				},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(HaveLen(1))
			Expect(rules[0].ToCIDR).To(ConsistOf([]ciliumapi.CIDR{
				ciliumapi.CIDR("10.0.0.0/32"),
				ciliumapi.CIDR("10.0.1.0/24"),
				ciliumapi.CIDR("10.0.2.0/25"),
			}))
		})

		DescribeTable("IP ranges", func(ipRange string, expectedCIDRs []ciliumapi.CIDR) {
			asgRules := []policy.SecurityGroupRule{
				{
					Destination: ipRange,
					Protocol:    "tcp",
					Ports:       "80",
				},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(HaveLen(1))
			Expect(rules[0].ToCIDR).To(ConsistOf(expectedCIDRs))
		},
			Entry("small range within a /24", "10.0.0.0-10.0.0.7", []ciliumapi.CIDR{ciliumapi.CIDR("10.0.0.0/29")}),
			Entry("complex range", "192.168.1.0-192.168.1.10", []ciliumapi.CIDR{
				ciliumapi.CIDR("192.168.1.0/29"),
				ciliumapi.CIDR("192.168.1.8/31"),
				ciliumapi.CIDR("192.168.1.10/32"),
			}),
			Entry("large range", "169.255.0.0-172.15.255.255", []ciliumapi.CIDR{
				ciliumapi.CIDR("169.255.0.0/16"),
				ciliumapi.CIDR("170.0.0.0/7"),
				ciliumapi.CIDR("172.0.0.0/12"),
			}),
			Entry("range that stops ", "255.255.255.250-255.255.255.255", []ciliumapi.CIDR{
				ciliumapi.CIDR("255.255.255.250/31"),
				ciliumapi.CIDR("255.255.255.252/30"),
			}),
			Entry("maximal range", "0.0.0.0-255.255.255.255", []ciliumapi.CIDR{
				ciliumapi.CIDR("0.0.0.0/0"),
			}),
			Entry("single ip ranges", "255.255.255.255-255.255.255.255,0.0.0.0-0.0.0.0,10.0.0.5-10.0.0.5", []ciliumapi.CIDR{
				ciliumapi.CIDR("255.255.255.255/32"),
				ciliumapi.CIDR("0.0.0.0/32"),
				ciliumapi.CIDR("10.0.0.5/32"),
			}),
		)

		It("fails if the IP is invalid", func() {
			asgRules := []policy.SecurityGroupRule{
				{
					Destination: "10.0.0.256-10.0.0.257",
					Protocol:    "tcp",
					Ports:       "80",
				},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(BeEmpty())
		})

		It("ignores invalid IP range", func() {
			asgRules := []policy.SecurityGroupRule{
				{
					Destination: "10.0.0.10-10.0.0.5",
					Protocol:    "tcp",
					Ports:       "80",
				},
			}
			rules := reconciler.CreateCiliumEgressRulesFromASG(asgRules)
			Expect(rules).To(BeEmpty())
		})
	})

	Describe("CreateCiliumEgressSelectorFromASG", func() {
		It("returns selector for staging only", func() {
			asg := policy.SecurityGroup{StagingDefault: true, RunningDefault: false}
			selectors := reconciler.CreateCiliumEgressSelectorsFromASG(asg)
			Expect(selectors[0].MatchExpressions).To(ContainElement(slimv1.LabelSelectorRequirement{
				Key:      "cloudfoundry.org/source-type",
				Operator: slimv1.LabelSelectorOpIn,
				Values:   []string{"STG"},
			}))
		})

		It("returns selector for running only", func() {
			asg := policy.SecurityGroup{StagingDefault: false, RunningDefault: true}
			selectors := reconciler.CreateCiliumEgressSelectorsFromASG(asg)
			Expect(selectors[0].MatchExpressions).To(ContainElement(slimv1.LabelSelectorRequirement{
				Key:      "cloudfoundry.org/source-type",
				Operator: slimv1.LabelSelectorOpNotIn,
				Values:   []string{"STG"},
			}))
		})

		It("returns selectors for running spaces", func() {
			asg := policy.SecurityGroup{
				RunningSpaceGuids: []string{"guid1", "guid2"},
			}
			selectors := reconciler.CreateCiliumEgressSelectorsFromASG(asg)
			Expect(selectors).To(ConsistOf(
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/space-guid",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"guid1", "guid2"},
						},
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpNotIn,
							Values:   []string{"STG"},
						},
					},
				},
			))
		})

		It("returns selectors for staging spaces", func() {
			asg := policy.SecurityGroup{
				StagingSpaceGuids: []string{"guid1", "guid2"},
			}
			selectors := reconciler.CreateCiliumEgressSelectorsFromASG(asg)
			Expect(selectors).To(ConsistOf(
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/space-guid",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"guid1", "guid2"},
						},
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"STG"},
						},
					},
				},
			))
		})

		It("returns selectors for running and staging spaces", func() {
			asg := policy.SecurityGroup{
				RunningSpaceGuids: []string{"guid1", "guid2"},
				StagingSpaceGuids: []string{"guid1", "guid2"},
			}
			selectors := reconciler.CreateCiliumEgressSelectorsFromASG(asg)
			Expect(selectors).To(ConsistOf(
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/space-guid",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"guid1", "guid2"},
						},
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpNotIn,
							Values:   []string{"STG"},
						},
					},
				},
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/space-guid",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"guid1", "guid2"},
						},
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"STG"},
						},
					},
				},
			))
		})

		It("returns selector for spaces which differ in running and staging", func() {
			asg := policy.SecurityGroup{
				RunningSpaceGuids: []string{"guid1"},
				StagingSpaceGuids: []string{"guid1", "guid2"},
			}
			selectors := reconciler.CreateCiliumEgressSelectorsFromASG(asg)
			Expect(selectors).To(ConsistOf(
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/space-guid",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"guid1"},
						},
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpNotIn,
							Values:   []string{"STG"},
						},
					},
				},
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/space-guid",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"guid1", "guid2"},
						},
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"STG"},
						},
					},
				},
			))
		})

		It("does not set source-type selector when staging and running default are true", func() {
			asg := policy.SecurityGroup{StagingDefault: true, RunningDefault: true}
			selectors := reconciler.CreateCiliumEgressSelectorsFromASG(asg)
			Expect(selectors).To(ConsistOf(
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"STG"},
						},
					},
				},
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpNotIn,
							Values:   []string{"STG"},
						},
					},
				},
			))
		})

		It("returns selectors for staging spaces with global running", func() {
			asg := policy.SecurityGroup{
				RunningDefault:    true,
				StagingSpaceGuids: []string{"guid1", "guid2"},
			}
			selectors := reconciler.CreateCiliumEgressSelectorsFromASG(asg)
			Expect(selectors).To(ConsistOf(
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpNotIn,
							Values:   []string{"STG"},
						},
					},
				},
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/space-guid",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"guid1", "guid2"},
						},
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"STG"},
						},
					},
				},
			))
		})

		It("returns selectors for running and staging spaces with global running", func() {
			asg := policy.SecurityGroup{
				RunningDefault:    true,
				RunningSpaceGuids: []string{"guid1", "guid2"},
				StagingSpaceGuids: []string{"guid1", "guid2"},
			}
			selectors := reconciler.CreateCiliumEgressSelectorsFromASG(asg)
			Expect(selectors).To(ConsistOf(
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpNotIn,
							Values:   []string{"STG"},
						},
					},
				},
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/space-guid",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"guid1", "guid2"},
						},
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpNotIn,
							Values:   []string{"STG"},
						},
					},
				},
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/space-guid",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"guid1", "guid2"},
						},
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"STG"},
						},
					},
				},
			))
		})

		It("returns selector for spaces which differ in running and staging and with global running", func() {
			asg := policy.SecurityGroup{
				RunningDefault:    true,
				RunningSpaceGuids: []string{"guid1"},
				StagingSpaceGuids: []string{"guid1", "guid2"},
			}
			selectors := reconciler.CreateCiliumEgressSelectorsFromASG(asg)
			Expect(selectors).To(ConsistOf(
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpNotIn,
							Values:   []string{"STG"},
						},
					},
				},
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/space-guid",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"guid1"},
						},
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpNotIn,
							Values:   []string{"STG"},
						},
					},
				},
				slimv1.LabelSelector{
					MatchExpressions: []slimv1.LabelSelectorRequirement{
						{
							Key:      "cloudfoundry.org/space-guid",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"guid1", "guid2"},
						},
						{
							Key:      "cloudfoundry.org/source-type",
							Operator: slimv1.LabelSelectorOpIn,
							Values:   []string{"STG"},
						},
					},
				},
			))
		})
	})
})
