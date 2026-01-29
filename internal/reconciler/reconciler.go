package reconciler

import (
	"context"
	"fmt"
	"strings"

	"code.cloudfoundry.org/k8s-policy-agent/internal/config"
	"code.cloudfoundry.org/k8s-policy-agent/internal/types"

	"code.cloudfoundry.org/lager/v3"
	policy "code.cloudfoundry.org/policy_client"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type networkPolicyReconciler struct {
	k8sclient client.Client
	config    *config.Config
	logger    lager.Logger
}

type Reconciler interface {
	Reconcile(securityGroups []policy.SecurityGroup, networkPolicies []*policy.Policy) error
}

func New(k8sclient client.Client, config *config.Config, logger lager.Logger) Reconciler {
	return &networkPolicyReconciler{
		k8sclient: k8sclient,
		config:    config,
		logger:    logger,
	}
}

func (r *networkPolicyReconciler) Reconcile(securityGroups []policy.SecurityGroup, networkPolicies []*policy.Policy) error {
	// Create a set of current security group GUIDs
	currentGUIDs := map[string]struct{}{}
	for _, asg := range securityGroups {
		currentGUIDs[asg.Guid] = struct{}{}
	}

	aggregatePolicies := map[string]map[string][]policy.Destination{}
	for _, p := range networkPolicies {
		currentGUIDs[fmt.Sprintf("c2c-%s", p.Source.ID)] = struct{}{}

		if _, exists := aggregatePolicies[p.Source.ID]; !exists {
			aggregatePolicies[p.Source.ID] = map[string][]policy.Destination{}
		}

		aggregatePolicies[p.Source.ID][p.Destination.ID] = append(aggregatePolicies[p.Source.ID][p.Destination.ID], p.Destination)
	}

	err := r.removeObsoleteNetworkPolicies(currentGUIDs)
	if err != nil {
		r.logger.Error("failed to remove obsolete network policies", err)
		return err
	}

	for _, asg := range securityGroups {
		cnp, err := r.translasteASGtoCiliumNetworkPolicy(asg)
		if err != nil {
			return fmt.Errorf("not able to translate ASG '%v': %w", asg, err)
		}

		if err := r.createOrUpdateNetworkPolicy(cnp); err != nil {
			r.logger.Error("failed to create/update CiliumNetworkPolicy", err, lager.Data{"asg_name": asg.Name})
			return err
		}
	}

	for sourceID, destinations := range aggregatePolicies {
		cnp, err := r.translatePolicyToCiliumNetworkPolicy(sourceID, destinations)
		if err != nil {
			return fmt.Errorf("not able to translate Policy for app %q: %w", sourceID, err)
		}

		if err := r.createOrUpdateNetworkPolicy(cnp); err != nil {
			r.logger.Error("failed to create/update CiliumNetworkPolicy", err, lager.Data{"policy_source_id": sourceID})
			return err
		}
	}

	return nil
}

func (r *networkPolicyReconciler) removeObsoleteNetworkPolicies(currentGUIDs map[string]struct{}) error {
	policies := &ciliumv2.CiliumNetworkPolicyList{}
	if err := r.k8sclient.List(context.Background(), policies, &client.ListOptions{
		LabelSelector: labels.SelectorFromValidatedSet(map[string]string{types.NetworkPoliciesAppLabelKey: types.NetworkPoliciesAppLabelValue}),
	}); err != nil {
		r.logger.Error("failed to list CiliumNetworkPolicies", err)
		return err
	}

	// Delete only policies whose names (GUIDs) are not in the current security groups
	for _, policy := range policies.Items {
		if _, exists := currentGUIDs[policy.Name]; !exists {
			err := r.k8sclient.Delete(context.Background(), &policy)
			if err != nil {
				r.logger.Error("failed to delete obsolete CiliumNetworkPolicy", err, lager.Data{"policy_name": policy.Name})
				return err
			}
			r.logger.Info("deleted obsolete CiliumNetworkPolicy", lager.Data{"policy_name": policy.Name})
		}
	}

	return nil
}

func (r *networkPolicyReconciler) translasteASGtoCiliumNetworkPolicy(asg policy.SecurityGroup) (*ciliumv2.CiliumNetworkPolicy, error) {
	egressRules := CreateCiliumEgressRulesFromASG(asg.Rules)

	specs := ciliumapi.Rules{}
	for _, selector := range CreateCiliumEgressSelectorsFromASG(asg) {
		specs = append(specs,
			&ciliumapi.Rule{
				Egress:           egressRules,
				EndpointSelector: ciliumapi.EndpointSelector{LabelSelector: &selector},
			},
		)
	}

	if len(specs) == 0 {
		return nil, fmt.Errorf("no specs created")
	}

	cnp := &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      asg.Guid,
			Namespace: r.config.Namespace,
			Labels: map[string]string{
				types.NetworkPoliciesAppLabelKey:      types.NetworkPoliciesAppLabelValue,
				types.NetworkPoliciesRuleNameLabelKey: asg.Name,
			},
		},
		Specs: specs,
	}
	return cnp, nil
}

func (r *networkPolicyReconciler) translatePolicyToCiliumNetworkPolicy(sourceID string, destinationMap map[string][]policy.Destination) (*ciliumv2.CiliumNetworkPolicy, error) {
	egressRules := []ciliumapi.EgressRule{}
	for destinationID, destinations := range destinationMap {
		egressRule := ciliumapi.EgressRule{
			EgressCommonRule: ciliumapi.EgressCommonRule{
				ToEndpoints: []ciliumapi.EndpointSelector{
					{
						LabelSelector: &slimv1.LabelSelector{
							MatchLabels: map[string]string{
								"cloudfoundry.org/app-guid": destinationID,
							},
						},
					},
				},
			},
			ToPorts: ciliumapi.PortRules{
				{
					Ports: []ciliumapi.PortProtocol{},
				},
			},
		}

		for _, dest := range destinations {
			egressRule.ToPorts[0].Ports = append(egressRule.ToPorts[0].Ports, ciliumapi.PortProtocol{
				Port:     fmt.Sprintf("%d", dest.Ports.Start),
				EndPort:  int32(dest.Ports.End),
				Protocol: ciliumapi.L4Proto(strings.ToUpper(dest.Protocol)),
			})
		}

		egressRules = append(egressRules, egressRule)
	}

	return &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("c2c-%s", sourceID),
			Namespace: r.config.Namespace,
			Labels: map[string]string{
				types.NetworkPoliciesAppLabelKey: types.NetworkPoliciesAppLabelValue,
			},
		},
		Specs: ciliumapi.Rules{
			&ciliumapi.Rule{
				EndpointSelector: ciliumapi.EndpointSelector{
					LabelSelector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"cloudfoundry.org/app-guid": sourceID,
						},
					},
				},
				Egress: egressRules,
			},
		},
	}, nil
}

func (r *networkPolicyReconciler) createOrUpdateNetworkPolicy(cnp *ciliumv2.CiliumNetworkPolicy) error {
	existing := &ciliumv2.CiliumNetworkPolicy{}
	if err := r.k8sclient.Get(context.Background(), client.ObjectKeyFromObject(cnp), existing); err != nil {
		if !apierrors.IsNotFound(err) {
			r.logger.Error("failed to get existing CiliumNetworkPolicy", err)
			return err
		}

		if err := r.k8sclient.Create(context.Background(), cnp); err != nil {
			r.logger.Error("failed to create CiliumNetworkPolicy", err)
			return err
		}

		r.logger.Info("created CiliumNetworkPolicy", lager.Data{"asg_guid": cnp.Name})
		return nil
	}

	cnp.ResourceVersion = existing.ResourceVersion

	if specsEqual(existing, cnp) {
		r.logger.Debug("unchanged CiliumNetworkPolicy, no update necessary", lager.Data{"asg_guid": cnp.Name})
		return nil
	}

	if err := r.k8sclient.Update(context.Background(), cnp); err != nil {
		r.logger.Error("failed to update CiliumNetworkPolicy", err)
		return err
	}

	r.logger.Debug("updated CiliumNetworkPolicy", lager.Data{"asg_guid": cnp.Name})
	return nil
}

func specsEqual(a, b *ciliumv2.CiliumNetworkPolicy) bool {
	return a.Specs.DeepEqual(&b.Specs)
}
