package agent

import (
	"net/http"

	"code.cloudfoundry.org/k8s-policy-agent/internal/config"

	"code.cloudfoundry.org/lager/v3"
	policy "code.cloudfoundry.org/policy_client"
	"code.cloudfoundry.org/tlsconfig"
)

//counterfeiter:generate . PolicyServerClient
type PolicyServerClient interface {
	GetSecurityGroupsForSpace(spaceGuids ...string) ([]policy.SecurityGroup, error)
	GetPolicies() ([]*policy.Policy, error)
}

type policyServerClient struct {
	internalClient *policy.InternalClient
}

func NewPolicyServerClient(logger lager.Logger, config *config.Config) (PolicyServerClient, error) {
	httpClient, err := newMTLSClient(config)
	if err != nil {
		return nil, err
	}

	internalClient := policy.NewInternal(logger, httpClient, config.PolicyServerURL, policy.Config{
		PerPageSecurityGroups: config.PerPageSecurityGroups,
	})

	return &policyServerClient{
		internalClient: internalClient,
	}, nil
}

func (p *policyServerClient) GetSecurityGroupsForSpace(spaceGuids ...string) ([]policy.SecurityGroup, error) {
	return p.internalClient.GetSecurityGroupsForSpace(spaceGuids...)
}

func (p *policyServerClient) GetPolicies() ([]*policy.Policy, error) {
	return p.internalClient.GetPolicies()
}

func newMTLSClient(config *config.Config) (*http.Client, error) {
	tlsConf, err := tlsconfig.Build(
		tlsconfig.WithInternalServiceDefaults(),
		tlsconfig.WithIdentityFromFile(config.TLSCertPath, config.TLSKeyPath),
	).Client(
		tlsconfig.WithAuthorityFromFile(config.TLSCAPath),
	)
	if err != nil {
		return nil, err
	}

	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}, nil
}
