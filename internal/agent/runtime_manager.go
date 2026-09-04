package agent

import (
	"context"

	"code.cloudfoundry.org/k8s-policy-agent/internal/cni"
	"code.cloudfoundry.org/k8s-policy-agent/internal/config"
	"code.cloudfoundry.org/k8s-policy-agent/internal/types"

	"code.cloudfoundry.org/lager/v3"
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
}

type runtimeManager struct {
	mgr        ctrlmanager.Manager
	translator cni.Translator
}

//counterfeiter:generate . RuntimeManager
type RuntimeManager interface {
	KubernetesClient() client.Client
	Translator() cni.Translator
	Add(r ctrlmanager.Runnable) error
	Start(ctx context.Context) error
}

func NewRuntimeManager(ctx context.Context, logger lager.Logger, config *config.Config) (RuntimeManager, error) {
	runtimeManager := &runtimeManager{
		translator: cni.NewTranslator(config.CNI, config.Namespace),
	}
	runtimeManager.translator.AddToScheme(scheme)

	podSelector, err := labels.NewRequirement(types.SpaceGUIDLabelKey, selection.Exists, nil)
	if err != nil {
		return nil, err
	}

	networkPolicySelector, err := labels.NewRequirement(types.NetworkPoliciesAppLabelKey, selection.Equals, []string{types.NetworkPoliciesAppLabelValue})
	if err != nil {
		return nil, err
	}

	runtimeManager.mgr, err = ctrlmanager.New(ctrl.GetConfigOrDie(), ctrlmanager.Options{
		Logger: klog.NewKlogr().V(3),
		Scheme: scheme,
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Pod{}: {
					Label: labels.NewSelector().Add(*podSelector),
				},
				runtimeManager.translator.GetType(): {
					Label: labels.NewSelector().Add(*networkPolicySelector),
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}

	if _, err := runtimeManager.mgr.GetCache().GetInformer(ctx, &corev1.Pod{}); err != nil {
		return nil, err
	}

	if _, err := runtimeManager.mgr.GetCache().GetInformer(ctx, runtimeManager.translator.GetType()); err != nil {
		return nil, err
	}

	return runtimeManager, nil
}

func (m *runtimeManager) KubernetesClient() client.Client {
	return m.mgr.GetClient()
}

func (m *runtimeManager) Translator() cni.Translator {
	return m.translator
}

func (m *runtimeManager) Add(r ctrlmanager.Runnable) error {
	return m.mgr.Add(r)
}

func (m *runtimeManager) Start(ctx context.Context) error {
	return m.mgr.Start(ctx)
}
