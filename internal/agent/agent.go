package agent

import (
	"context"
	"time"

	"code.cloudfoundry.org/k8s-policy-agent/internal/config"
	"code.cloudfoundry.org/k8s-policy-agent/internal/reconciler"
	"code.cloudfoundry.org/k8s-policy-agent/internal/types"

	"code.cloudfoundry.org/lager/v3"
	policy "code.cloudfoundry.org/policy_client"
	corev1 "k8s.io/api/core/v1"

	ctrlmanager "sigs.k8s.io/controller-runtime/pkg/manager"

	clnt "sigs.k8s.io/controller-runtime/pkg/client"
)

type policyAgent struct {
	k8sclient    clnt.Client
	policyClient PolicyServerClient
	reconciler   reconciler.Reconciler
	config       *config.Config
	logger       lager.Logger
	ticker       *time.Ticker
	ctx          context.Context
}

var _ ctrlmanager.Runnable = &policyAgent{}

func New(k8sclient clnt.Client, policyClient PolicyServerClient, reconciler reconciler.Reconciler, config *config.Config, logger lager.Logger) ctrlmanager.Runnable {
	return &policyAgent{
		k8sclient:    k8sclient,
		policyClient: policyClient,
		reconciler:   reconciler,
		config:       config,
		logger:       logger,
	}
}

func (a *policyAgent) Start(ctx context.Context) error {
	a.ctx = ctx
	a.ticker = time.NewTicker(a.config.PollInterval)

	a.logger.Info("policy-agent started", lager.Data{
		"poll_interval": a.config.PollInterval,
		"namespace":     a.config.Namespace,
	})

	for {
		a.reconcile()

		select {
		case <-a.ticker.C:
			continue
		case <-a.ctx.Done():
			a.ticker.Stop()
			a.logger.Info("policy-agent stopped")
			return nil
		}
	}
}

func (a *policyAgent) reconcile() {
	policies, err := a.policyClient.GetPolicies()
	if err != nil {
		a.logger.Error("error fetching policies", err, lager.Data{
			"policy_server_url": a.config.PolicyServerURL,
		})
		return
	}

	securityGroups, err := a.fetchSecurityGroups()
	if err != nil {
		a.logger.Error("error fetching security groups", err, lager.Data{
			"policy_server_url": a.config.PolicyServerURL,
		})
		return
	}

	if err := a.reconciler.Reconcile(securityGroups, policies); err != nil {
		a.logger.Error("error reconciling security groups", err)
	}
}

func (a *policyAgent) fetchSecurityGroups() ([]policy.SecurityGroup, error) {
	pods := &corev1.PodList{}
	if err := a.k8sclient.List(context.Background(), pods); err != nil {
		a.logger.Error("error listing pods", err)
		return nil, err
	}

	spaceGUIDSet := map[string]struct{}{}
	for _, pod := range pods.Items {
		if label, exists := pod.GetLabels()[types.SpaceGUIDLabelKey]; exists {
			spaceGUIDSet[label] = struct{}{}
		}
	}

	spaceGUIDs := []string{}
	for guid := range spaceGUIDSet {
		spaceGUIDs = append(spaceGUIDs, guid)
	}

	a.logger.Info("checking pods", lager.Data{
		"count":       len(pods.Items),
		"space_guids": len(spaceGUIDs),
	})

	return a.policyClient.GetSecurityGroupsForSpace(spaceGUIDs...)
}
