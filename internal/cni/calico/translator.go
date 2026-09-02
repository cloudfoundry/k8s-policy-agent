package calico

import (
	"errors"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"

	"code.cloudfoundry.org/k8s-policy-agent/internal/cni/util"
	"code.cloudfoundry.org/k8s-policy-agent/internal/types"

	policy "code.cloudfoundry.org/policy_client"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	projectcalicoapi "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

const (
	appGUIDLabelKey    = "cloudfoundry.org/app-guid"
	sourceTypeLabelKey = "cloudfoundry.org/source-type"
	stagingSourceType  = "STG"
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
func (t *translator) TranslateASG(asg policy.SecurityGroup) (client.Object, error) {
	selector := createCalicoEgressSelectorFromASG(asg)
	if selector == "" {
		return nil, fmt.Errorf("no specs created")
	}

	return &projectcalicoapi.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      asg.Guid,
			Namespace: t.namespace,
			Labels: map[string]string{
				types.NetworkPoliciesAppLabelKey:      types.NetworkPoliciesAppLabelValue,
				types.NetworkPoliciesRuleNameLabelKey: asg.Name,
			},
		},
		Spec: projectcalicoapi.NetworkPolicySpec{
			Selector: selector,
			Types:    []projectcalicoapi.PolicyType{projectcalicoapi.PolicyTypeEgress},
			Egress:   createCalicoEgressRulesFromASG(asg.Rules),
		},
	}, nil
}

// TranslatePolicy implements [cni.Translator].
func (t *translator) TranslatePolicy(sourceID string, destinationMap map[string][]policy.Destination) (client.Object, error) {
	egressRules := []projectcalicoapi.Rule{}

	destinationIDs := make([]string, 0, len(destinationMap))
	for destinationID := range destinationMap {
		destinationIDs = append(destinationIDs, destinationID)
	}
	slices.Sort(destinationIDs)

	for _, destinationID := range destinationIDs {
		for _, dest := range destinationMap[destinationID] {
			port, err := numorstring.PortFromRange(uint16(dest.Ports.Start), uint16(dest.Ports.End))
			if err != nil {
				log.Printf("invalid port range %d-%d (destination will be ignored): %v", dest.Ports.Start, dest.Ports.End, err)
				continue
			}

			egressRules = append(egressRules, projectcalicoapi.Rule{
				Action:   projectcalicoapi.Allow,
				Protocol: new(numorstring.ProtocolFromString(strings.ToUpper(dest.Protocol))),
				Destination: projectcalicoapi.EntityRule{
					Selector: equalsSelector(appGUIDLabelKey, destinationID),
					Ports:    []numorstring.Port{port},
				},
			})
		}
	}

	return &projectcalicoapi.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("c2c-%s", sourceID),
			Namespace: t.namespace,
			Labels: map[string]string{
				types.NetworkPoliciesAppLabelKey: types.NetworkPoliciesAppLabelValue,
			},
		},
		Spec: projectcalicoapi.NetworkPolicySpec{
			Selector: equalsSelector(appGUIDLabelKey, sourceID),
			Types:    []projectcalicoapi.PolicyType{projectcalicoapi.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}, nil
}

func createCalicoEgressRulesFromASG(asgRules []policy.SecurityGroupRule) []projectcalicoapi.Rule {
	var calicoEgressRules []projectcalicoapi.Rule

	for _, rule := range asgRules {
		nets := []string{}
		for destination := range strings.SplitSeq(rule.Destination, ",") {
			cidrs, err := translateToCidrs(destination)
			if err != nil {
				log.Printf("invalid destination %q (rule will be ignored): %v", destination, err)
				continue
			}
			nets = append(nets, cidrs...)
		}
		if len(nets) == 0 {
			log.Printf("no valid destination found in %q (rule will be ignored)", rule.Destination)
			continue
		}

		egressRule := projectcalicoapi.Rule{
			Action: projectcalicoapi.Allow,
			Destination: projectcalicoapi.EntityRule{
				Nets: nets,
			},
		}

		switch rule.Protocol {
		case "tcp":
			egressRule.Protocol = new(numorstring.ProtocolFromString(numorstring.ProtocolTCP))
			egressRule.Destination.Ports = toPorts(rule.Ports)
		case "udp":
			egressRule.Protocol = new(numorstring.ProtocolFromString(numorstring.ProtocolUDP))
			egressRule.Destination.Ports = toPorts(rule.Ports)
		case "icmp":
			egressRule.Protocol = new(numorstring.ProtocolFromString(numorstring.ProtocolICMP))
			egressRule.IPVersion = new(4)
			egressRule.ICMP = icmpFields(rule.Type, rule.Code)
		case "icmpv6":
			egressRule.Protocol = new(numorstring.ProtocolFromString(numorstring.ProtocolICMPv6))
			egressRule.IPVersion = new(6)
			egressRule.ICMP = icmpFields(rule.Type, rule.Code)
		case "all":
			// do not set any protocol, ports or ICMP fields to allow all protocols for given destinations
		default:
			// we need to continue for unsupported protocols to
			// avoid adding empty rules which would allow all traffic
			log.Printf("unsupported protocol %q (rule will be ignored)", rule.Protocol)
			continue
		}

		calicoEgressRules = append(calicoEgressRules, egressRule)
	}

	return calicoEgressRules
}

func toPorts(portStr string) []numorstring.Port {
	if portStr == "" {
		portStr = "1-65535"
	}

	var ports []numorstring.Port
	for port := range strings.SplitSeq(portStr, ",") {
		portRange := strings.SplitN(strings.TrimSpace(port), "-", 2)

		startPort, err := strconv.ParseUint(portRange[0], 10, 16)
		if err != nil {
			continue
		}

		endPort := startPort
		if len(portRange) == 2 {
			endPort, err = strconv.ParseUint(portRange[1], 10, 16)
			if err != nil {
				continue
			}
		}

		parsedPort, err := numorstring.PortFromRange(uint16(startPort), uint16(endPort))
		if err != nil {
			continue
		}

		ports = append(ports, parsedPort)
	}
	return ports
}

// a nil result makes Calico match all ICMP types and codes
func icmpFields(icmpType, icmpCode int) *projectcalicoapi.ICMPFields {
	if icmpType < 0 {
		return nil
	}

	fields := &projectcalicoapi.ICMPFields{Type: new(icmpType)}
	if icmpCode >= 0 {
		fields.Code = new(icmpCode)
	}

	return fields
}

func translateToCidrs(destination string) ([]string, error) {
	if destination == "" {
		return nil, errors.New("empty destination")
	}

	if strings.Contains(destination, "/") {
		return []string{destination}, nil
	}

	if strings.Contains(destination, "-") {
		return util.RangeToCIDRs(destination)
	}

	return []string{destination + "/32"}, nil
}

// createCalicoEgressSelectorFromASG creates a selector expression based on ASG metadata
func createCalicoEgressSelectorFromASG(asg policy.SecurityGroup) string {
	selectors := []string{}

	if asg.StagingDefault && asg.RunningDefault {
		return "has(cloudfoundry.org/app-guid)"
	}

	if asg.StagingDefault {
		selectors = append(selectors, equalsSelector(sourceTypeLabelKey, stagingSourceType))
	}

	if asg.RunningDefault {
		selectors = append(selectors, notEqualsSelector(sourceTypeLabelKey, stagingSourceType))
	}

	if len(asg.RunningSpaceGuids) > 0 {
		selectors = append(selectors, fmt.Sprintf("(%s && %s)",
			inSelector(types.SpaceGUIDLabelKey, asg.RunningSpaceGuids),
			notEqualsSelector(sourceTypeLabelKey, stagingSourceType),
		))
	}

	if len(asg.StagingSpaceGuids) > 0 {
		selectors = append(selectors, fmt.Sprintf("(%s && %s)",
			inSelector(types.SpaceGUIDLabelKey, asg.StagingSpaceGuids),
			notEqualsSelector(sourceTypeLabelKey, stagingSourceType),
		))
	}

	return strings.Join(selectors, " || ")
}

func equalsSelector(key, value string) string {
	return fmt.Sprintf("%s == %s", key, strconv.Quote(value))
}

func notEqualsSelector(key, value string) string {
	return fmt.Sprintf("%s != %s", key, strconv.Quote(value))
}

func inSelector(key string, values []string) string {
	return fmt.Sprintf("%s in {%s}", key, quoteIndividual(values))
}

func quoteIndividual(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = strconv.Quote(value)
	}

	return strings.Join(quoted, ", ")
}
