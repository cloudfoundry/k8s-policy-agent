package cni

import (
	"code.cloudfoundry.org/k8s-policy-agent/internal/cni/calico"
	"code.cloudfoundry.org/k8s-policy-agent/internal/cni/cilium"
	policy "code.cloudfoundry.org/policy_client"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Translator interface {
	AddToScheme(scheme *runtime.Scheme)
	GetType() client.Object
	GetListType() client.ObjectList
	TranslateASG(policy.SecurityGroup) (client.Object, error)
	TranslatePolicy(string, map[string][]policy.Destination) (client.Object, error)
	Equals(client.Object, client.Object) bool
}

func NewTranslator(cni, namespace string) Translator {
	switch cni {
	case "calico":
		return calico.NewTranslator(namespace)
	case "cilium":
		return cilium.NewTranslator(namespace)
	default:
		panic("unsupported CNI type: " + cni)
	}

}
