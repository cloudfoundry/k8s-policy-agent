package reconciler

import (
	"context"
	"fmt"

	"code.cloudfoundry.org/k8s-policy-agent/internal/cni"
	"code.cloudfoundry.org/k8s-policy-agent/internal/config"
	"code.cloudfoundry.org/k8s-policy-agent/internal/types"

	"code.cloudfoundry.org/lager/v3"
	policy "code.cloudfoundry.org/policy_client"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type networkPolicyReconciler struct {
	k8sclient  client.Client
	config     *config.Config
	logger     lager.Logger
	translator cni.Translator
}

type Reconciler interface {
	Reconcile(securityGroups []policy.SecurityGroup, networkPolicies []*policy.Policy) error
}

func New(k8sclient client.Client, translator cni.Translator, config *config.Config, logger lager.Logger) Reconciler {
	return &networkPolicyReconciler{
		k8sclient:  k8sclient,
		config:     config,
		logger:     logger,
		translator: translator,
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
		netpol, err := r.translator.TranslateASG(asg)
		if err != nil {
			return fmt.Errorf("not able to translate ASG '%v': %w", asg, err)
		}

		if err := r.createOrUpdateNetworkPolicy(netpol); err != nil {
			r.logger.Error("failed to create/update network policy", err, lager.Data{"asg_name": asg.Name})
			return err
		}
	}

	for sourceID, destinations := range aggregatePolicies {
		netpol, err := r.translator.TranslatePolicy(sourceID, destinations)
		if err != nil {
			return fmt.Errorf("not able to translate Policy for app %q: %w", sourceID, err)
		}

		if err := r.createOrUpdateNetworkPolicy(netpol); err != nil {
			r.logger.Error("failed to create/update network policy", err, lager.Data{"policy_source_id": sourceID})
			return err
		}
	}

	return nil
}

func (r *networkPolicyReconciler) removeObsoleteNetworkPolicies(currentGUIDs map[string]struct{}) error {
	policies := r.translator.GetListType()
	if err := r.k8sclient.List(context.Background(), policies, &client.ListOptions{
		LabelSelector: labels.SelectorFromValidatedSet(map[string]string{types.NetworkPoliciesAppLabelKey: types.NetworkPoliciesAppLabelValue}),
	}); err != nil {
		r.logger.Error("failed to list CiliumNetworkPolicies", err)
		return err
	}

	return meta.EachListItem(policies, func(obj runtime.Object) error {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return fmt.Errorf("failed to cast object to client.Object: %w", err)
		}

		if _, exists := currentGUIDs[accessor.GetName()]; !exists {
			err := r.k8sclient.Delete(context.Background(), accessor.(client.Object))
			if err != nil {
				r.logger.Error("failed to delete obsolete CiliumNetworkPolicy", err, lager.Data{"policy_name": accessor.GetName()})
				return err
			}
			r.logger.Info("deleted obsolete CiliumNetworkPolicy", lager.Data{"policy_name": accessor.GetName()})
		}

		return nil
	})
}

func (r *networkPolicyReconciler) createOrUpdateNetworkPolicy(obj client.Object) error {
	existing := obj.DeepCopyObject().(client.Object)
	if err := r.k8sclient.Get(context.Background(), client.ObjectKeyFromObject(obj), existing); err != nil {
		if !apierrors.IsNotFound(err) {
			r.logger.Error("failed to get existing CiliumNetworkPolicy", err)
			return err
		}

		if err := r.k8sclient.Create(context.Background(), obj); err != nil {
			r.logger.Error("failed to create CiliumNetworkPolicy", err)
			return err
		}

		r.logger.Info("created CiliumNetworkPolicy", lager.Data{"asg_guid": obj.GetName()})
		return nil
	}

	obj.SetResourceVersion(existing.GetResourceVersion())

	if r.translator.Equals(existing, obj) {
		r.logger.Debug("unchanged CiliumNetworkPolicy, no update necessary", lager.Data{"asg_guid": obj.GetName()})
		return nil
	}

	if err := r.k8sclient.Update(context.Background(), obj); err != nil {
		r.logger.Error("failed to update CiliumNetworkPolicy", err)
		return err
	}

	r.logger.Debug("updated CiliumNetworkPolicy", lager.Data{"asg_guid": obj.GetName()})
	return nil
}
