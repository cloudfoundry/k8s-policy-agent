package agent

import (
	"context"

	"code.cloudfoundry.org/k8s-policy-agent/internal/config"
	"code.cloudfoundry.org/k8s-policy-agent/internal/types"

	"code.cloudfoundry.org/lager/v3"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlmanager "sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(ciliumv2.AddToScheme(scheme))
}

type runtimeManager struct {
	runtimeManager ctrlmanager.Manager
}

//counterfeiter:generate . RuntimeManager
type RuntimeManager interface {
	KubernetesClient() client.Client
	Add(r ctrlmanager.Runnable) error
	Start(ctx context.Context) error
}

func NewRuntimeManager(ctx context.Context, logger lager.Logger, config *config.Config) (RuntimeManager, error) {
	podSelector, err := labels.NewRequirement(types.SpaceGUIDLabelKey, selection.Exists, nil)
	if err != nil {
		return nil, err
	}

	networkPolicySelector, err := labels.NewRequirement(types.NetworkPoliciesAppLabelKey, selection.Equals, []string{types.NetworkPoliciesAppLabelValue})
	if err != nil {
		return nil, err
	}

	mgr, err := ctrlmanager.New(ctrl.GetConfigOrDie(), ctrlmanager.Options{
		Logger: klog.NewKlogr().V(3),
		Scheme: scheme,
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Pod{}: {
					Label: labels.NewSelector().Add(*podSelector),
				},
				&ciliumv2.CiliumNetworkPolicy{}: {
					Label: labels.NewSelector().Add(*networkPolicySelector),
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	if _, err := mgr.GetCache().GetInformer(ctx, &corev1.Pod{}); err != nil {
		return nil, err
	}

	if _, err := mgr.GetCache().GetInformer(ctx, &ciliumv2.CiliumNetworkPolicy{}); err != nil {
		return nil, err
	}

	return &runtimeManager{
		runtimeManager: mgr,
	}, nil
}

func (m *runtimeManager) KubernetesClient() client.Client {
	return m.runtimeManager.GetClient()
}

func (m *runtimeManager) Add(r ctrlmanager.Runnable) error {
	return m.runtimeManager.Add(r)
}

func (m *runtimeManager) Start(ctx context.Context) error {
	return m.runtimeManager.Start(ctx)
}
