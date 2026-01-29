package config_test

import (
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"code.cloudfoundry.org/k8s-policy-agent/internal/config"
)

func setEnvWithCleanup(k, v string) {
	original := os.Getenv(k)
	Expect(os.Setenv(k, v)).To(Succeed())
	DeferCleanup(func() {
		if original == "" {
			Expect(os.Unsetenv(k)).To(Succeed())
		} else {
			Expect(os.Setenv(k, original)).To(Succeed())
		}
	})
}

var _ = Describe("Config", func() {
	Describe("Load", func() {
		DescribeTable("successful load scenarios", func(vars map[string]string, expected *config.Config) {
			for k, v := range vars {
				setEnvWithCleanup(k, v)
			}

			cfg := config.Load()
			Expect(cfg).To(Equal(expected))
		},
			Entry("all values overridden", map[string]string{
				"POLICY_SERVER_URL":        "http://example.com",
				"NAMESPACE":                "custom-ns",
				"POLL_INTERVAL":            "42s",
				"PER_PAGE_SECURITY_GROUPS": "77",
				"TLS_CERT_PATH":            "/custom/cert",
				"TLS_KEY_PATH":             "/custom/key",
				"TLS_CA_PATH":              "/custom/ca",
			}, &config.Config{
				PolicyServerURL:       "http://example.com",
				Namespace:             "custom-ns",
				PollInterval:          42 * time.Second,
				PerPageSecurityGroups: 77,
				TLSCertPath:           "/custom/cert",
				TLSKeyPath:            "/custom/key",
				TLSCAPath:             "/custom/ca",
			}),
			Entry("only required variable set, defaults applied", map[string]string{
				"POLICY_SERVER_URL": "http://example.com",
			}, &config.Config{
				PolicyServerURL:       "http://example.com",
				Namespace:             config.DefaultNamespace,
				PollInterval:          config.DefaultPollInterval,
				PerPageSecurityGroups: config.DefaultPerPageSecurityGroups,
				TLSCertPath:           config.DefaultTLSCertPath,
				TLSKeyPath:            config.DefaultTLSKeyPath,
				TLSCAPath:             config.DefaultTLSCAPath,
			}),
		)

		Describe("numeric parsing", func() {
			BeforeEach(func() {
				setEnvWithCleanup("POLICY_SERVER_URL", "http://example.com")
			})

			It("falls back when poll interval is invalid", func() {
				setEnvWithCleanup("POLL_INTERVAL", "notanumber")
				Expect(config.Load().PollInterval).To(Equal(config.DefaultPollInterval))
			})

			It("falls back when per page groups is invalid", func() {
				setEnvWithCleanup("PER_PAGE_SECURITY_GROUPS", "notanumber")
				Expect(config.Load().PerPageSecurityGroups).To(Equal(config.DefaultPerPageSecurityGroups))
			})

			It("falls back when poll interval is zero", func() {
				setEnvWithCleanup("POLL_INTERVAL", "0")
				Expect(config.Load().PollInterval).To(Equal(config.DefaultPollInterval))
			})

			It("falls back when poll interval is negative", func() {
				setEnvWithCleanup("POLL_INTERVAL", "-5")
				Expect(config.Load().PollInterval).To(Equal(config.DefaultPollInterval))
			})
		})

		Describe("failure cases", func() {
			It("panics with helpful message if POLICY_SERVER_URL is missing", func() {
				Expect(os.Unsetenv("POLICY_SERVER_URL")).To(Succeed())
				Expect(func() { config.Load() }).To(PanicWith(ContainSubstring("POLICY_SERVER_URL")))
			})
		})
	})
})
