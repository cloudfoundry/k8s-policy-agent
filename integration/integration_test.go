package integration_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func init() {
	utilruntime.Must(ciliumv2.AddToScheme(scheme.Scheme))
}

var clt client.Client

var _ = Describe("PolicyAgent", Ordered, func() {
	var echoContainer testcontainers.Container

	BeforeAll(func() {
		var err error
		clt, err = client.New(config.GetConfigOrDie(), client.Options{})
		Expect(err).NotTo(HaveOccurred())

		// start test container outside cluster
		ctx := context.Background()
		req := testcontainers.ContainerRequest{
			Networks:     []string{"kind"},
			Image:        "nginx:latest",
			ExposedPorts: []string{"80/tcp"},
			WaitingFor:   wait.ForHTTP("/").WithPort("80/tcp"),
		}
		echoContainer, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
		Expect(err).NotTo(HaveOccurred())
		clt, err = client.New(config.GetConfigOrDie(), client.Options{})
		Expect(err).NotTo(HaveOccurred())

		waitForWorkloads()
	})

	AfterAll(func() {
		if echoContainer != nil {
			ctx := context.Background()
			Expect(echoContainer.Terminate(ctx)).To(Succeed())
		}
	})

	AfterEach(func() {
		err := applyToPostgres("./fixtures/sql/cleanup.sql")
		Expect(err).NotTo(HaveOccurred())
		waitForPolicies(0)
	})

	Describe("HTTP connectivity", func() {
		It("allows to differ between global staging and global running", func() {
			ip, err := echoContainer.ContainerIP(context.TODO())
			fmt.Printf("Echo container IP: %s\n", ip)
			Expect(err).NotTo(HaveOccurred())

			By("Not having any ASG")
			waitForPolicies(0)

			shouldHaveHTTPConnectivity("staging-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, false)

			By("Having an ASG for global staging")
			err = applyToPostgres("./fixtures/sql/global_staging.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(1)

			shouldHaveHTTPConnectivity("staging-pod", ip, true)
			shouldHaveHTTPConnectivity("running-pod", ip, false)

			By("Also having an ASG for global running")
			err = applyToPostgres("./fixtures/sql/global_running.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(2)

			shouldHaveHTTPConnectivity("staging-pod", ip, true)
			shouldHaveHTTPConnectivity("running-pod", ip, true)

			By("Not having any ASG again")
			err = applyToPostgres("./fixtures/sql/cleanup.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(0)

			shouldHaveHTTPConnectivity("staging-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, false)

		})

		It("allows to differ between spaces", func() {
			ip, err := echoContainer.ContainerIP(context.TODO())
			Expect(err).NotTo(HaveOccurred())

			By("Not having any ASG")
			waitForPolicies(0)

			shouldHaveHTTPConnectivity("different-space-running-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, false)

			By("Having a space bound ASG")
			err = applyToPostgres("./fixtures/sql/space_bound.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(1)

			shouldHaveHTTPConnectivity("different-space-running-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, true)

			By("Also having an ASG for a different space")
			err = applyToPostgres("./fixtures/sql/different_space_bound.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(2)

			shouldHaveHTTPConnectivity("different-space-running-pod", ip, true)
			shouldHaveHTTPConnectivity("running-pod", ip, true)

			By("Not having any ASG again")
			err = applyToPostgres("./fixtures/sql/cleanup.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(0)

			shouldHaveHTTPConnectivity("different-space-running-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, false)
		})

		It("allows to differ between global running and space staging", func() {
			ip, err := echoContainer.ContainerIP(context.TODO())
			Expect(err).NotTo(HaveOccurred())

			By("Not having any ASG")
			waitForPolicies(0)

			shouldHaveHTTPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveHTTPConnectivity("different-space-running-pod", ip, false)
			shouldHaveHTTPConnectivity("staging-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, false)

			By("Having a global running ASG")
			err = applyToPostgres("./fixtures/sql/global_running.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(1)

			shouldHaveHTTPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveHTTPConnectivity("different-space-running-pod", ip, true)
			shouldHaveHTTPConnectivity("staging-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, true)

			By("Also having an ASG for staging pod")
			err = applyToPostgres("./fixtures/sql/space_bound.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(2)

			shouldHaveHTTPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveHTTPConnectivity("different-space-running-pod", ip, true)
			shouldHaveHTTPConnectivity("staging-pod", ip, true)
			shouldHaveHTTPConnectivity("running-pod", ip, true)

			By("Not having any ASG again")
			err = applyToPostgres("./fixtures/sql/cleanup.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(0)

			shouldHaveHTTPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveHTTPConnectivity("different-space-running-pod", ip, false)
			shouldHaveHTTPConnectivity("staging-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, false)
		})

		It("applies a global and space bound ASG correctly", func() {
			ip, err := echoContainer.ContainerIP(context.TODO())
			Expect(err).NotTo(HaveOccurred())

			By("Not having any ASG")
			waitForPolicies(0)

			shouldHaveHTTPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveHTTPConnectivity("different-space-running-pod", ip, false)
			shouldHaveHTTPConnectivity("staging-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, false)

			By("Having a global running and space staging ASG")
			err = applyToPostgres("./fixtures/sql/global_and_space_bound.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(1)

			shouldHaveHTTPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveHTTPConnectivity("different-space-running-pod", ip, true)
			shouldHaveHTTPConnectivity("staging-pod", ip, true)
			shouldHaveHTTPConnectivity("running-pod", ip, true)

			By("Not having any ASG again")
			err = applyToPostgres("./fixtures/sql/cleanup.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(0)

			shouldHaveHTTPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveHTTPConnectivity("different-space-running-pod", ip, false)
			shouldHaveHTTPConnectivity("staging-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, false)
		})

		It("applies an ASG with space bound ICMP rules correctly", func() {
			ip, err := echoContainer.ContainerIP(context.TODO())
			Expect(err).NotTo(HaveOccurred())

			By("Not having any ASG")
			waitForPolicies(0)

			shouldHaveICMPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveICMPConnectivity("different-space-running-pod", ip, false)
			shouldHaveICMPConnectivity("staging-pod", ip, false)
			shouldHaveICMPConnectivity("running-pod", ip, false)

			By("Having an ASG with ICMP bound to running space")
			err = applyToPostgres("./fixtures/sql/icmp.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(1)

			shouldHaveICMPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveICMPConnectivity("different-space-running-pod", ip, false)
			shouldHaveICMPConnectivity("staging-pod", ip, false)
			shouldHaveICMPConnectivity("running-pod", ip, true)

			By("Not having any ASG again")
			err = applyToPostgres("./fixtures/sql/cleanup.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(0)

			shouldHaveICMPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveICMPConnectivity("different-space-running-pod", ip, false)
			shouldHaveICMPConnectivity("staging-pod", ip, false)
			shouldHaveICMPConnectivity("running-pod", ip, false)
		})

		It("applies an ASG with 'all' protocols correctly", func() {
			ip, err := echoContainer.ContainerIP(context.TODO())
			Expect(err).NotTo(HaveOccurred())

			By("Not having any ASG")
			waitForPolicies(0)

			shouldHaveHTTPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveHTTPConnectivity("different-space-running-pod", ip, false)
			shouldHaveICMPConnectivity("different-space-running-pod", ip, false)
			shouldHaveHTTPConnectivity("staging-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, false)
			shouldHaveICMPConnectivity("running-pod", ip, false)

			By("Having an ASG with all protocol bound to running space")
			err = applyToPostgres("./fixtures/sql/all.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(1)

			shouldHaveHTTPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveHTTPConnectivity("different-space-running-pod", ip, false)
			shouldHaveICMPConnectivity("different-space-running-pod", ip, false)
			shouldHaveHTTPConnectivity("staging-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, true)
			shouldHaveICMPConnectivity("running-pod", ip, true)

			By("Not having any ASG again")
			err = applyToPostgres("./fixtures/sql/cleanup.sql")
			Expect(err).NotTo(HaveOccurred())

			waitForPolicies(0)

			shouldHaveHTTPConnectivity("different-space-staging-pod", ip, false)
			shouldHaveHTTPConnectivity("different-space-running-pod", ip, false)
			shouldHaveICMPConnectivity("different-space-running-pod", ip, false)
			shouldHaveHTTPConnectivity("staging-pod", ip, false)
			shouldHaveHTTPConnectivity("running-pod", ip, false)
			shouldHaveICMPConnectivity("running-pod", ip, false)
		})
	})
})

func wgetPort80(pod string, destination string) bool {
	cmd := exec.Command("kubectl", "exec", "-n", "cf-workloads", pod, "--", "wget", "--timeout", "1", "-O", "-", fmt.Sprintf("http://%s:80", destination))
	_, err := cmd.CombinedOutput()
	return err == nil
}

func ping(pod string, destination string) bool {
	cmd := exec.Command("kubectl", "exec", "-n", "cf-workloads", pod, "--", "ping", "-c", "1", "-W", "1", destination)
	_, err := cmd.CombinedOutput()
	return err == nil
}

func shouldHaveHTTPConnectivity(pod string, destination string, expected bool) {
	Eventually(func() bool {
		return wgetPort80(pod, destination)
	}, "2m", "1s").To(Equal(expected))
}

func shouldHaveICMPConnectivity(pod string, destination string, expected bool) {
	Eventually(func() bool {
		return ping(pod, destination)
	}, "2m", "1s").To(Equal(expected))
}

func waitForWorkloads() {
	EventuallyWithOffset(1, func() bool {
		pods := &corev1.PodList{}
		err := clt.List(context.Background(), pods, &client.ListOptions{Namespace: "cf-workloads"})

		for _, pod := range pods.Items {
			if pod.Status.Phase != corev1.PodRunning {
				return false
			}
			for _, container := range pod.Status.ContainerStatuses {
				if container.State.Running == nil {
					return false
				}
			}
		}
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		return true
	}, "1m", "10s").To(Equal(true))
}

func waitForPolicies(expected int) {
	EventuallyWithOffset(1, func() int {
		policies := &ciliumv2.CiliumNetworkPolicyList{}
		err := clt.List(context.Background(), policies, &client.ListOptions{})
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		return len(policies.Items)
	}, "2m", "1s").To(Equal(expected))
}

func applyToPostgres(filename string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	cmd := exec.Command("kubectl", "exec", "-n", "default", "postgres-postgresql-0", "--", "sh", "-c", fmt.Sprintf("PGPASSWORD=postgres psql -U postgres -d network_policy -c \"%s\"", string(content)))
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		return fmt.Errorf("error applying %s: %v, output: %s", filename, err, string(out))
	}
	return nil
}
