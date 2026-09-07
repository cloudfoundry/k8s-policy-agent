package cilium_test

import (
	policy "code.cloudfoundry.org/policy_client"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"code.cloudfoundry.org/k8s-policy-agent/internal/cni"
)

var _ = Describe("Translator", func() {
	var translator cni.Translator

	BeforeEach(func() {
		translator = cni.NewTranslator("cilium", "default")
	})

	translate := func(asg policy.SecurityGroup) *ciliumv2.CiliumNetworkPolicy {
		if !asg.StagingDefault && !asg.RunningDefault && len(asg.RunningSpaceGuids) == 0 && len(asg.StagingSpaceGuids) == 0 {
			asg.RunningDefault = true
		}
		translated, err := translator.TranslateASG(asg)
		Expect(err).NotTo(HaveOccurred())
		return translated.(*ciliumv2.CiliumNetworkPolicy)
	}

	Describe("TranslateASG", func() {
		It("translates TCP ports", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.1", Protocol: "tcp", Ports: "80,443"}}}).Specs[0].Egress[0]
			Expect(rule.ToCIDR).To(ConsistOf(ciliumapi.CIDR("10.0.0.1/32")))
			Expect(rule.ToPorts).To(HaveLen(2))
			Expect(rule.ToPorts[0].Ports[0].Port).To(Equal("80"))
			Expect(rule.ToPorts[0].Ports[0].Protocol).To(Equal(ciliumapi.ProtoTCP))
			Expect(rule.ToPorts[1].Ports[0].Port).To(Equal("443"))
		})

		It("translates UDP ports and ranges", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.2/24", Protocol: "udp", Ports: "53-54"}}}).Specs[0].Egress[0]
			Expect(rule.ToCIDR).To(ConsistOf(ciliumapi.CIDR("10.0.0.2/24")))
			Expect(rule.ToPorts[0].Ports[0]).To(Equal(ciliumapi.PortProtocol{Port: "53", EndPort: 54, Protocol: ciliumapi.ProtoUDP}))
		})

		It("uses all ports when ports are empty", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.4", Protocol: "tcp"}}}).Specs[0].Egress[0]
			Expect(rule.ToPorts).To(ConsistOf(ciliumapi.PortRule{Ports: []ciliumapi.PortProtocol{{Port: "1", EndPort: 65535, Protocol: ciliumapi.ProtoTCP}}}))
		})

		It("translates ICMP and ICMPv6 types", func() {
			translated := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{
				{Destination: "10.0.0.8", Protocol: "icmp", Type: 8},
				{Destination: "2001:db8::8", Protocol: "icmpv6", Type: 128},
			}})
			Expect(translated.Specs[0].Egress[0].ICMPs[0].Fields[0].Family).To(Equal(ciliumapi.IPv4Family))
			Expect(translated.Specs[0].Egress[0].ICMPs[0].Fields[0].Type.IntVal).To(Equal(int32(8)))
			Expect(translated.Specs[0].Egress[1].ICMPs[0].Fields[0].Family).To(Equal(ciliumapi.IPv6Family))
		})

		It("expands a negative ICMP type", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.8", Protocol: "icmp", Type: -1}}}).Specs[0].Egress[0]
			Expect(rule.ICMPs[0].Fields).NotTo(BeEmpty())
			Expect(rule.ToPorts).To(BeEmpty())
		})

		It("leaves ports and ICMP unset for all traffic", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.9/24", Protocol: "all"}}}).Specs[0].Egress[0]
			Expect(rule.ToCIDR).To(ConsistOf(ciliumapi.CIDR("10.0.0.9/24")))
			Expect(rule.ToPorts).To(BeEmpty())
			Expect(rule.ICMPs).To(BeEmpty())
		})

		It("translates comma-delimited destinations and ranges", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.0,10.0.1.0/24,10.0.2.0-10.0.2.127", Protocol: "tcp", Ports: "80"}}}).Specs[0].Egress[0]
			Expect(rule.ToCIDR).To(ConsistOf(ciliumapi.CIDR("10.0.0.0/32"), ciliumapi.CIDR("10.0.1.0/24"), ciliumapi.CIDR("10.0.2.0/25")))
		})

		It("ignores unsupported and invalid rules", func() {
			translated := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{
				{Destination: "10.0.0.3", Protocol: "foo", Ports: "1234"},
				{Destination: "", Protocol: "tcp", Ports: "80"},
				{Destination: "10.0.0.10-10.0.0.5", Protocol: "tcp", Ports: "80"},
			}})
			Expect(translated.Specs[0].Egress).To(BeEmpty())
		})

		It("returns an error for an ASG without a selector", func() {
			_, err := translator.TranslateASG(policy.SecurityGroup{})
			Expect(err).To(MatchError("no specs created"))
		})
	})

	Describe("ASG selectors", func() {
		It("creates a staging-only selector", func() {
			translated := translate(policy.SecurityGroup{StagingDefault: true})
			Expect(translated.Specs).To(HaveLen(1))
			Expect(translated.Specs[0].EndpointSelector.LabelSelector.MatchExpressions).To(ContainElement(slimv1.LabelSelectorRequirement{Key: "cloudfoundry.org/source-type", Operator: slimv1.LabelSelectorOpIn, Values: []string{"STG"}}))
		})

		It("creates a running-only selector", func() {
			translated := translate(policy.SecurityGroup{RunningDefault: true})
			Expect(translated.Specs[0].EndpointSelector.LabelSelector.MatchExpressions).To(ContainElement(slimv1.LabelSelectorRequirement{Key: "cloudfoundry.org/source-type", Operator: slimv1.LabelSelectorOpNotIn, Values: []string{"STG"}}))
		})

		It("creates selectors for running and staging spaces independently", func() {
			translated := translate(policy.SecurityGroup{RunningSpaceGuids: []string{"guid1", "guid2"}, StagingSpaceGuids: []string{"guid1", "guid2"}})
			Expect(translated.Specs).To(HaveLen(2))
			Expect(translated.Specs[0].EndpointSelector.LabelSelector.MatchExpressions).To(ContainElements(
				slimv1.LabelSelectorRequirement{Key: "cloudfoundry.org/space-guid", Operator: slimv1.LabelSelectorOpIn, Values: []string{"guid1", "guid2"}},
				slimv1.LabelSelectorRequirement{Key: "cloudfoundry.org/source-type", Operator: slimv1.LabelSelectorOpNotIn, Values: []string{"STG"}},
			))
			Expect(translated.Specs[1].EndpointSelector.LabelSelector.MatchExpressions).To(ContainElements(
				slimv1.LabelSelectorRequirement{Key: "cloudfoundry.org/space-guid", Operator: slimv1.LabelSelectorOpIn, Values: []string{"guid1", "guid2"}},
				slimv1.LabelSelectorRequirement{Key: "cloudfoundry.org/source-type", Operator: slimv1.LabelSelectorOpIn, Values: []string{"STG"}},
			))
		})

		It("creates default selectors", func() {
			translated := translate(policy.SecurityGroup{StagingDefault: true, RunningDefault: true})
			Expect(translated.Specs).To(HaveLen(1))
			Expect(translated.Specs[0].EndpointSelector.LabelSelector.MatchExpressions).To(ContainElement(slimv1.LabelSelectorRequirement{Key: "cloudfoundry.org/app-guid", Operator: slimv1.LabelSelectorOpExists}))
		})

		It("creates selectors for running and staging spaces", func() {
			translated := translate(policy.SecurityGroup{RunningSpaceGuids: []string{"guid1"}, StagingSpaceGuids: []string{"guid2"}})
			Expect(translated.Specs).To(HaveLen(2))
			Expect(translated.Specs[0].EndpointSelector.LabelSelector.MatchExpressions).To(ContainElement(slimv1.LabelSelectorRequirement{Key: "cloudfoundry.org/space-guid", Operator: slimv1.LabelSelectorOpIn, Values: []string{"guid1"}}))
			Expect(translated.Specs[1].EndpointSelector.LabelSelector.MatchExpressions).To(ContainElement(slimv1.LabelSelectorRequirement{Key: "cloudfoundry.org/space-guid", Operator: slimv1.LabelSelectorOpIn, Values: []string{"guid2"}}))
		})
	})
})
