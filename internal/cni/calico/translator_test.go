package calico_test

import (
	policy "code.cloudfoundry.org/policy_client"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"code.cloudfoundry.org/k8s-policy-agent/internal/cni"
)

var _ = Describe("Translator", func() {
	var translator cni.Translator

	BeforeEach(func() {
		translator = cni.NewTranslator("calico", "default")
	})

	translate := func(asg policy.SecurityGroup) *v3.NetworkPolicy {
		if !asg.StagingDefault && !asg.RunningDefault && len(asg.RunningSpaceGuids) == 0 && len(asg.StagingSpaceGuids) == 0 {
			asg.RunningDefault = true
		}
		translated, err := translator.TranslateASG(asg)
		Expect(err).NotTo(HaveOccurred())
		return translated.(*v3.NetworkPolicy)
	}

	Describe("TranslateASG", func() {
		It("translates TCP ports", func() {
			translated := translate(policy.SecurityGroup{Guid: "guid", Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.1", Protocol: "tcp", Ports: "80,443"}}})
			rule := translated.Spec.Egress[0]
			Expect(translated.Spec.Egress).To(HaveLen(1))
			Expect(rule.Destination.Nets).To(ConsistOf("10.0.0.1/32"))
			Expect(rule.Destination.Ports).To(ConsistOf(numorstring.Port{MinPort: 80, MaxPort: 80}, numorstring.Port{MinPort: 443, MaxPort: 443}))
			Expect(*rule.Protocol).To(Equal(numorstring.ProtocolFromString(numorstring.ProtocolTCP)))
		})

		It("translates UDP ports", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.2/24", Protocol: "udp", Ports: "53-54"}}}).Spec.Egress[0]
			Expect(rule.Destination.Nets).To(ConsistOf("10.0.0.2/24"))
			Expect(rule.Destination.Ports).To(ConsistOf(numorstring.Port{MinPort: 53, MaxPort: 54}))
			Expect(*rule.Protocol).To(Equal(numorstring.ProtocolFromString(numorstring.ProtocolUDP)))
		})

		It("uses all ports when ports are empty", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.4", Protocol: "tcp"}}}).Spec.Egress[0]
			Expect(rule.Destination.Ports).To(ConsistOf(numorstring.Port{MinPort: 1, MaxPort: 65535}))
		})

		It("translates ICMP type and code", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.8", Protocol: "icmp", Type: 8, Code: 0}}}).Spec.Egress[0]
			Expect(*rule.Protocol).To(Equal(numorstring.ProtocolFromString(numorstring.ProtocolICMP)))
			Expect(*rule.IPVersion).To(Equal(4))
			Expect(rule.Destination.Ports).To(BeEmpty())
			Expect(rule.ICMP).NotTo(BeNil())
			Expect(*rule.ICMP.Type).To(Equal(8))
			Expect(*rule.ICMP.Code).To(Equal(0))
		})

		It("matches all ICMP types and codes for negative type", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.8", Protocol: "icmp", Type: -1}}}).Spec.Egress[0]
			Expect(rule.ICMP).To(BeNil())
		})

		It("translates ICMPv6", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "2001:db8::8", Protocol: "icmpv6", Type: 128}}}).Spec.Egress[0]
			Expect(*rule.Protocol).To(Equal(numorstring.ProtocolFromString(numorstring.ProtocolICMPv6)))
			Expect(*rule.IPVersion).To(Equal(6))
			Expect(*rule.ICMP.Type).To(Equal(128))
		})

		It("leaves protocol unset for all traffic", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.9/24", Protocol: "all"}}}).Spec.Egress[0]
			Expect(rule.Protocol).To(BeNil())
			Expect(rule.Destination.Ports).To(BeEmpty())
			Expect(rule.ICMP).To(BeNil())
		})

		It("translates comma-delimited destinations and IP ranges", func() {
			rule := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.0,10.0.1.0/24,10.0.2.0-10.0.2.127", Protocol: "tcp", Ports: "80"}}}).Spec.Egress[0]
			Expect(rule.Destination.Nets).To(ConsistOf("10.0.0.0/32", "10.0.1.0/24", "10.0.2.0/25"))
		})

		It("ignores unsupported and invalid rules", func() {
			translated := translate(policy.SecurityGroup{Rules: []policy.SecurityGroupRule{
				{Destination: "10.0.0.3", Protocol: "foo", Ports: "1234"},
				{Destination: "", Protocol: "tcp", Ports: "80"},
				{Destination: "10.0.0.10-10.0.0.5", Protocol: "tcp", Ports: "80"},
			}})
			Expect(translated.Spec.Egress).To(BeEmpty())
		})

		It("returns an error for an empty ASG", func() {
			_, err := translator.TranslateASG(policy.SecurityGroup{})
			Expect(err).To(MatchError("no specs created"))
		})
	})

	Describe("ASG selectors", func() {
		It("creates selectors for staging and running defaults", func() {
			translated := translate(policy.SecurityGroup{Guid: "guid", StagingDefault: true, RunningDefault: true, Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.1", Protocol: "all"}}})
			Expect(translated.Spec.Selector).To(Equal(`has(cloudfoundry.org/app-guid)`))
		})

		It("creates selectors for running and staging spaces", func() {
			translated := translate(policy.SecurityGroup{Guid: "guid", RunningSpaceGuids: []string{"guid1", "guid2"}, StagingSpaceGuids: []string{"guid1"}, Rules: []policy.SecurityGroupRule{{Destination: "10.0.0.1", Protocol: "all"}}})
			Expect(translated.Spec.Selector).To(Equal(`(cloudfoundry.org/space-guid in {"guid1", "guid2"} && cloudfoundry.org/source-type != "STG") || (cloudfoundry.org/space-guid in {"guid1"} && cloudfoundry.org/source-type != "STG")`))
		})
	})
})
