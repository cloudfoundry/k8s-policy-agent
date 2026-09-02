package calico

import (
	"code.cloudfoundry.org/policy_client"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	projectcalicoapi "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

type translator struct {
	namespace string
}

func NewTranslator(namespace string) *translator {
	return &translator{
		namespace: namespace,
	}
}

// AddToScheme implements [cni.Translator].
func (t *translator) AddToScheme(scheme *runtime.Scheme) {
	utilruntime.Must(projectcalicoapi.AddToScheme(scheme))
}

// Equals implements [cni.Translator].
func (t *translator) Equals(a, b client.Object) bool {
	return apiequality.Semantic.DeepEqual(a.(*projectcalicoapi.NetworkPolicy).Spec, b.(*projectcalicoapi.NetworkPolicy).Spec)
}

// GetListType implements [cni.Translator].
func (t *translator) GetListType() client.ObjectList {
	return &projectcalicoapi.NetworkPolicyList{}
}

// GetType implements [cni.Translator].
func (t *translator) GetType() client.Object {
	return &projectcalicoapi.NetworkPolicy{}
}

// TranslateASG implements [cni.Translator].
func (t *translator) TranslateASG(policy_client.SecurityGroup) (client.Object, error) {
	panic("unimplemented")
}

// TranslatePolicy implements [cni.Translator].
func (t *translator) TranslatePolicy(string, map[string][]policy_client.Destination) (client.Object, error) {
	panic("unimplemented")
}
