package agent_test

import (
	"context"
	"io"
	"time"

	"code.cloudfoundry.org/k8s-policy-agent/internal/agent"
	"code.cloudfoundry.org/k8s-policy-agent/internal/agent/agentfakes"
	agentconfig "code.cloudfoundry.org/k8s-policy-agent/internal/config"
	"code.cloudfoundry.org/k8s-policy-agent/internal/reconciler"

	policy "code.cloudfoundry.org/policy_client"

	"code.cloudfoundry.org/lager/v3"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"k8s.io/client-go/kubernetes/scheme"

	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrlmanager "sigs.k8s.io/controller-runtime/pkg/manager"
)

func init() {
	utilruntime.Must(ciliumv2.AddToScheme(scheme.Scheme))
}

var _ = Describe("Agent", func() {
	var (
		logger lager.Logger
		config *agentconfig.Config

		ctx                context.Context
		cancel             context.CancelFunc
		policyAgent        ctrlmanager.Runnable
		fakePolicyClient   *agentfakes.FakePolicyServerClient
		fakeReconciler     reconciler.Reconciler
		fakeClient         ctrlclient.Client
		fakeRuntimeManager *agentfakes.FakeRuntimeManager
	)

	BeforeEach(func() {
		logger = lager.NewLogger("reconciler-test")
		logger.RegisterSink(lager.NewWriterSink(io.Discard, lager.DEBUG))

		config = &agentconfig.Config{
			Namespace:    "default",
			PollInterval: 1 * time.Second,
		}

		fakePolicyClient = &agentfakes.FakePolicyServerClient{}
		fakeClient = fake.NewFakeClient()

		fakeRuntimeManager = &agentfakes.FakeRuntimeManager{}
		fakeRuntimeManager.KubernetesClientReturns(fakeClient)

		fakeReconciler = reconciler.New(fakeClient, config, logger)
		ctx, cancel = context.WithCancel(context.Background())
	})

	AfterEach(func() {
		cancel()
	})

	Describe("Start", func() {
		It("processes security groups and C2C policies", func() {
			fakePolicyClient.GetPoliciesReturns([]*policy.Policy{
				{
					Source: policy.Source{ID: "app-guid-1"},
					Destination: policy.Destination{
						ID:       "app-guid-2",
						Protocol: "tcp",
						Ports:    policy.Ports{Start: 8080, End: 8080},
					},
				},
			}, nil)
			fakePolicyClient.GetSecurityGroupsForSpaceStub = func(spaceGuids ...string) ([]policy.SecurityGroup, error) {
				return []policy.SecurityGroup{
					{
						Guid: "test-sg-guid-123",
						Name: "test-sg-name",
						Rules: policy.SecurityGroupRules{
							{
								Protocol:    "tcp",
								Destination: "1.1.1.1/32",
								Ports:       "80",
							},
						},
						StagingDefault: true,
					},
				}, nil
			}
			// Add test pods to the fake indexer
			testPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: config.Namespace,
					Labels: map[string]string{
						"cloudfoundry.org/space-guid": "test-space-guid-123",
					},
				},
			}
			Expect(fakeClient.Create(context.Background(), testPod)).To(Succeed())

			policyAgent = agent.New(fakeClient, fakePolicyClient, fakeReconciler, config, logger)

			agentDone := make(chan struct{})
			go func() {
				defer GinkgoRecover()

				Expect(policyAgent.Start(ctx)).To(Succeed())
				close(agentDone)
			}()
			Eventually(func() []ciliumv2.CiliumNetworkPolicy {
				policies := &ciliumv2.CiliumNetworkPolicyList{}
				Expect(fakeClient.List(context.Background(), policies, ctrlclient.InNamespace(config.Namespace))).To(Succeed())

				return policies.Items
			}).To(HaveLen(2))

			Expect(fakePolicyClient.GetPoliciesCallCount()).To(BeNumerically(">", 0))
			Expect(fakePolicyClient.GetSecurityGroupsForSpaceCallCount()).To(BeNumerically(">", 0))

			cancel()
			<-agentDone
		})
	})
})
