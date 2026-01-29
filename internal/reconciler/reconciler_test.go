package reconciler_test

import (
	"bytes"
	"context"
	"io"

	agentconfig "code.cloudfoundry.org/k8s-policy-agent/internal/config"
	"code.cloudfoundry.org/k8s-policy-agent/internal/reconciler"

	"code.cloudfoundry.org/lager/v3"
	policy "code.cloudfoundry.org/policy_client"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	. "github.com/onsi/gomega/gstruct"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
)

func init() {
	utilruntime.Must(ciliumv2.AddToScheme(scheme.Scheme))
}

var _ = Describe("Reconciler", func() {
	var (
		logger     lager.Logger
		config     *agentconfig.Config
		fakeClient ctrlclient.Client
	)

	BeforeEach(func() {
		logger = lager.NewLogger("reconciler-test")
		logger.RegisterSink(lager.NewWriterSink(io.Discard, lager.DEBUG))

		config = &agentconfig.Config{
			Namespace: "default",
		}

		fakeClient = fake.NewFakeClient()
	})

	Describe("New", func() {
		It("creates a Reconciler instance", func() {
			reconciler := reconciler.New(fakeClient, config, logger)
			Expect(reconciler).NotTo(BeNil())
		})
	})

	Describe("Reconcile", func() {
		It("removes obsolete security groups and C2C policies", func() {
			fakeClient = fake.NewFakeClient(
				&ciliumv2.CiliumNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "old-asg",
						Namespace: config.Namespace,
						Labels: map[string]string{
							"app":       "policy-agent",
							"rule-name": "old-asg",
						},
					},
				},
				&ciliumv2.CiliumNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "c2c-old-app-guid",
						Namespace: config.Namespace,
						Labels: map[string]string{
							"app":       "policy-agent",
							"rule-name": "c2c-old-app-guid",
						},
					},
				},
			)
			reconciler := reconciler.New(fakeClient, config, logger)

			Expect(reconciler.Reconcile(nil, nil)).To(BeNil())

			policies := ciliumv2.CiliumNetworkPolicyList{}
			Expect(fakeClient.List(context.Background(), &policies, ctrlclient.InNamespace(config.Namespace))).To(Succeed())
			Expect(policies.Items).To(HaveLen(0))
		})

		It("should raise error for noop policy", func() {
			reconciler := reconciler.New(fakeClient, config, logger)

			Expect(reconciler.Reconcile([]policy.SecurityGroup{
				{
					Guid: "tcp",
					Name: "tcp",
					Rules: []policy.SecurityGroupRule{
						{
							Destination: "1.1.1.1/32",
							Protocol:    "tcp",
							Ports:       "80,443",
						},
					},
				}}, []*policy.Policy{})).To(MatchError(ContainSubstring("no specs")))
		})

		It("creates new security groups and C2C policies", func() {
			reconciler := reconciler.New(fakeClient, config, logger)
			Expect(reconciler.Reconcile([]policy.SecurityGroup{
				{
					Guid: "tcp",
					Name: "tcp",
					Rules: []policy.SecurityGroupRule{
						{
							Destination: "1.1.1.1/32",
							Protocol:    "tcp",
							Ports:       "80,443",
						},
					},
					StagingDefault: true,
				},
				{
					Guid: "udp",
					Name: "udp",
					Rules: []policy.SecurityGroupRule{
						{
							Destination: "2.2.2.2/16",
							Protocol:    "udp",
							Ports:       "80",
						},
					},
					StagingDefault: true,
				},
				{
					Guid: "icmp",
					Name: "icmp",
					Rules: []policy.SecurityGroupRule{
						{
							Destination: "3.3.3.3",
							Protocol:    "icmp",
							Ports:       "80,443",
						},
					},
					StagingDefault: true,
				},
				{
					Guid: "any",
					Name: "any",
					Rules: []policy.SecurityGroupRule{
						{
							Destination: "2.2.2.2",
							Ports:       "443",
						},
					},
					StagingDefault: true,
				},
			}, []*policy.Policy{
				{
					Source: policy.Source{ID: "app-guid-1"},
					Destination: policy.Destination{
						ID:       "app-guid-2",
						Protocol: "tcp",
						Ports:    policy.Ports{Start: 8080, End: 8080},
					},
				},
				{
					Source: policy.Source{ID: "app-guid-3"},
					Destination: policy.Destination{
						ID:       "app-guid-4",
						Protocol: "udp",
						Ports:    policy.Ports{Start: 5353, End: 5353},
					},
				},
			})).To(BeNil())

			policies := ciliumv2.CiliumNetworkPolicyList{}
			Expect(fakeClient.List(context.Background(), &policies, ctrlclient.InNamespace(config.Namespace))).To(Succeed())
			Expect(policies.Items).To(HaveLen(6))

			Expect(policies.Items).To(ContainElements(
				MatchFields(IgnoreExtras, Fields{
					"ObjectMeta": MatchFields(IgnoreExtras, Fields{
						"Name":      Equal("tcp"),
						"Namespace": Equal(config.Namespace),
						"Labels": MatchKeys(IgnoreExtras, Keys{
							"app":       Equal("policy-agent"),
							"rule-name": Equal("tcp"),
						}),
					}),
				}),
				MatchFields(IgnoreExtras, Fields{
					"ObjectMeta": MatchFields(IgnoreExtras, Fields{
						"Name":      Equal("udp"),
						"Namespace": Equal(config.Namespace),
						"Labels": MatchKeys(IgnoreExtras, Keys{
							"app":       Equal("policy-agent"),
							"rule-name": Equal("udp"),
						}),
					}),
				}),
				MatchFields(IgnoreExtras, Fields{
					"ObjectMeta": MatchFields(IgnoreExtras, Fields{
						"Name":      Equal("icmp"),
						"Namespace": Equal(config.Namespace),
						"Labels": MatchKeys(IgnoreExtras, Keys{
							"app":       Equal("policy-agent"),
							"rule-name": Equal("icmp"),
						}),
					}),
				}),
				MatchFields(IgnoreExtras, Fields{
					"ObjectMeta": MatchFields(IgnoreExtras, Fields{
						"Name":      Equal("any"),
						"Namespace": Equal(config.Namespace),
						"Labels": MatchKeys(IgnoreExtras, Keys{
							"app":       Equal("policy-agent"),
							"rule-name": Equal("any"),
						}),
					}),
				}),
				MatchFields(IgnoreExtras, Fields{
					"ObjectMeta": MatchFields(IgnoreExtras, Fields{
						"Name": Equal("c2c-app-guid-1"),
					}),
				}),
				MatchFields(IgnoreExtras, Fields{
					"ObjectMeta": MatchFields(IgnoreExtras, Fields{
						"Name": Equal("c2c-app-guid-3"),
					}),
				}),
			))
		})

		It("updates existing security groups and C2C policies", func() {
			asgPolicy := &ciliumv2.CiliumNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tcp",
					Namespace: config.Namespace,
					Labels: map[string]string{
						"app":       "policy-agent",
						"rule-name": "tcp",
					},
				},
				Specs: ciliumapi.Rules{
					&ciliumapi.Rule{
						Egress: []ciliumapi.EgressRule{
							{
								EgressCommonRule: ciliumapi.EgressCommonRule{
									ToCIDR: ciliumapi.CIDRSlice{
										ciliumapi.CIDR("2.2.2.2"),
									},
								},
								ToPorts: ciliumapi.PortRules{
									{
										Ports: []ciliumapi.PortProtocol{
											{
												Port:     "8080",
												Protocol: ciliumapi.ProtoTCP,
											},
										},
									},
								},
							},
						},
					},
				},
			}
			c2cPolicy := &ciliumv2.CiliumNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "c2c-app-guid-1",
					Namespace: config.Namespace,
					Labels: map[string]string{
						"app":       "policy-agent",
						"rule-name": "c2c-app-guid-1",
					},
				},
				Specs: ciliumapi.Rules{
					&ciliumapi.Rule{
						Egress: []ciliumapi.EgressRule{
							{
								ToPorts: ciliumapi.PortRules{
									{
										Ports: []ciliumapi.PortProtocol{
											{
												Port:     "9000",
												Protocol: ciliumapi.ProtoTCP,
											},
										},
									},
								},
							},
						},
					},
				},
			}
			fakeClient = fake.NewFakeClient(asgPolicy, c2cPolicy)

			reconciler := reconciler.New(fakeClient, config, logger)
			Expect(reconciler.Reconcile([]policy.SecurityGroup{
				{
					Guid:           "tcp",
					Name:           "tcp",
					StagingDefault: true,
					Rules: []policy.SecurityGroupRule{
						{
							Destination: "1.1.1.1/32",
							Protocol:    "tcp",
							Ports:       "80",
						},
					},
				},
			}, []*policy.Policy{
				{
					Source: policy.Source{ID: "app-guid-1"},
					Destination: policy.Destination{
						ID:       "app-guid-2",
						Protocol: "tcp",
						Ports:    policy.Ports{Start: 8080, End: 8080},
					},
				},
			})).To(Succeed())

			Expect(fakeClient.Get(context.Background(), ctrlclient.ObjectKeyFromObject(asgPolicy), asgPolicy)).To(Succeed())
			Expect(asgPolicy.ObjectMeta.Name).To(Equal("tcp"))
			Expect(asgPolicy.Specs).To(HaveLen(1))
			Expect(asgPolicy.Specs[0].Egress).To(HaveLen(1))
			Expect(asgPolicy.Specs[0].Egress[0].ToCIDR).To(ConsistOf(ciliumapi.CIDR("1.1.1.1/32")))
			Expect(asgPolicy.Specs[0].Egress[0].ToPorts).To(ConsistOf(ciliumapi.PortRule{
				Ports: []ciliumapi.PortProtocol{
					{
						Port:     "80",
						EndPort:  80,
						Protocol: ciliumapi.ProtoTCP,
					},
				},
			}))

			Expect(fakeClient.Get(context.Background(), ctrlclient.ObjectKeyFromObject(c2cPolicy), c2cPolicy)).To(Succeed())
			Expect(c2cPolicy.ObjectMeta.Name).To(Equal("c2c-app-guid-1"))
			Expect(c2cPolicy.Specs).To(HaveLen(1))
			Expect(c2cPolicy.Specs[0].Egress).To(HaveLen(1))
			Expect(c2cPolicy.Specs[0].Egress[0].ToPorts[0].Ports).To(ContainElement(MatchFields(IgnoreExtras, Fields{
				"Port":     Equal("8080"),
				"EndPort":  Equal(int32(8080)),
				"Protocol": Equal(ciliumapi.ProtoTCP),
			})))
		})

		It("skips update of unchanged security groups", func() {
			asg := []policy.SecurityGroup{
				{
					Guid:           "tcp",
					Name:           "tcp",
					StagingDefault: true,
					Rules: []policy.SecurityGroupRule{
						{
							Destination: "4.4.4.4/32",
							Protocol:    "tcp",
							Ports:       "8082",
						},
					},
				},
			}
			ciliumPolicy := &ciliumv2.CiliumNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tcp",
					Namespace: config.Namespace,
					Labels: map[string]string{
						"app":       "policy-agent",
						"rule-name": "tcp",
					},
				},
				Specs: ciliumapi.Rules{
					&ciliumapi.Rule{
						EndpointSelector: ciliumapi.EndpointSelector{
							LabelSelector: &slimv1.LabelSelector{
								MatchExpressions: []slimv1.LabelSelectorRequirement{
									{
										Key:      "cloudfoundry.org/source-type",
										Operator: slimv1.LabelSelectorOpIn,
										Values:   []string{"STG"},
									},
								},
							},
						},
						Egress: []ciliumapi.EgressRule{
							{
								EgressCommonRule: ciliumapi.EgressCommonRule{
									ToCIDR: ciliumapi.CIDRSlice{
										ciliumapi.CIDR("4.4.4.4/32"),
									},
								},
								ToPorts: ciliumapi.PortRules{
									{
										Ports: []ciliumapi.PortProtocol{
											{
												Port:     "8082",
												EndPort:  8082,
												Protocol: ciliumapi.ProtoTCP,
											},
										},
									},
								},
							},
						},
					},
				},
			}

			logger = lager.NewLogger("reconciler-test")
			var logBuffer bytes.Buffer
			logger.RegisterSink(lager.NewWriterSink(&logBuffer, lager.DEBUG))

			fakeClient = fake.NewFakeClient(ciliumPolicy)
			reconciler := reconciler.New(fakeClient, config, logger)
			Expect(reconciler.Reconcile(asg, []*policy.Policy{})).To(Succeed())

			logs := logBuffer.String()
			Expect(logs).To(ContainSubstring("unchanged"))
		})

		It("aggregates multiple C2C policies for the same source and destination", func() {
			reconciler := reconciler.New(fakeClient, config, logger)

			policies := []*policy.Policy{
				{
					Source: policy.Source{ID: "app-guid-1"},
					Destination: policy.Destination{
						ID:       "app-guid-2",
						Protocol: "tcp",
						Ports:    policy.Ports{Start: 8080, End: 8080},
					},
				},
				{
					Source: policy.Source{ID: "app-guid-1"},
					Destination: policy.Destination{
						ID:       "app-guid-2",
						Protocol: "tcp",
						Ports:    policy.Ports{Start: 9090, End: 9090},
					},
				},
			}

			Expect(reconciler.Reconcile(nil, policies)).To(Succeed())

			cnpList := ciliumv2.CiliumNetworkPolicyList{}
			Expect(fakeClient.List(context.Background(), &cnpList, ctrlclient.InNamespace(config.Namespace))).To(Succeed())
			Expect(cnpList.Items).To(HaveLen(1))

			cnp := cnpList.Items[0]
			Expect(cnp.Name).To(Equal("c2c-app-guid-1"))
			Expect(cnp.Specs[0].Egress).To(HaveLen(1))
			Expect(cnp.Specs[0].Egress[0].ToPorts[0].Ports).To(HaveLen(2))
		})

		It("creates separate egress rules for different C2C destinations", func() {
			reconciler := reconciler.New(fakeClient, config, logger)

			policies := []*policy.Policy{
				{
					Source: policy.Source{ID: "app-guid-1"},
					Destination: policy.Destination{
						ID:       "app-guid-2",
						Protocol: "tcp",
						Ports:    policy.Ports{Start: 8080, End: 8080},
					},
				},
				{
					Source: policy.Source{ID: "app-guid-1"},
					Destination: policy.Destination{
						ID:       "app-guid-3",
						Protocol: "tcp",
						Ports:    policy.Ports{Start: 9090, End: 9090},
					},
				},
			}

			Expect(reconciler.Reconcile(nil, policies)).To(Succeed())

			cnpList := ciliumv2.CiliumNetworkPolicyList{}
			Expect(fakeClient.List(context.Background(), &cnpList, ctrlclient.InNamespace(config.Namespace))).To(Succeed())
			Expect(cnpList.Items).To(HaveLen(1))

			cnp := cnpList.Items[0]
			Expect(cnp.Name).To(Equal("c2c-app-guid-1"))
			Expect(cnp.Specs[0].Egress).To(HaveLen(2))
		})
	})
})
