package cilium

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"code.cloudfoundry.org/k8s-policy-agent/internal/cni/util"
	"code.cloudfoundry.org/k8s-policy-agent/internal/types"
	"code.cloudfoundry.org/policy_client"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policy "code.cloudfoundry.org/policy_client"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
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
	utilruntime.Must(ciliumv2.AddToScheme(scheme))
}

// Equals implements [cni.Translator].
func (t *translator) Equals(a client.Object, b client.Object) bool {
	return a.(*ciliumv2.CiliumNetworkPolicy).Specs.DeepEqual(ptr.To(b.(*ciliumv2.CiliumNetworkPolicy).Specs))
}

// GetListType implements [cni.Translator].
func (t *translator) GetListType() client.ObjectList {
	return &ciliumv2.CiliumNetworkPolicyList{}
}

// GetType implements [cni.Translator].
func (t *translator) GetType() client.Object {
	return &ciliumv2.CiliumNetworkPolicy{}
}

// TranslateASG implements [cni.Translator].
func (t *translator) TranslateASG(asg policy_client.SecurityGroup) (client.Object, error) {
	egressRules := createCiliumEgressRulesFromASG(asg.Rules)

	specs := ciliumapi.Rules{}
	for _, selector := range createCiliumEgressSelectorsFromASG(asg) {
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
			Namespace: t.namespace,
			Labels: map[string]string{
				types.NetworkPoliciesAppLabelKey:      types.NetworkPoliciesAppLabelValue,
				types.NetworkPoliciesRuleNameLabelKey: asg.Name,
			},
		},
		Specs: specs,
	}
	return cnp, nil
}

// TranslatePolicy implements [cni.Translator].
func (t *translator) TranslatePolicy(sourceID string, destinationMap map[string][]policy_client.Destination) (client.Object, error) {
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
			Namespace: t.namespace,
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

func createCiliumEgressRulesFromASG(asgRules []policy.SecurityGroupRule) []ciliumapi.EgressRule {
	var ciliumEgressRules []ciliumapi.EgressRule

	for _, rule := range asgRules {
		cidrsList := []ciliumapi.CIDR{}
		for destination := range strings.SplitSeq(rule.Destination, ",") {
			cidrs, err := translateToCidrs(destination)
			if err != nil {
				log.Printf("invalid destination %q (rule will be ignored): %v", destination, err)
				continue
			}
			cidrsList = append(cidrsList, cidrs...)
		}
		if len(cidrsList) == 0 {
			log.Printf("no valid destination found in %q (rule will be ignored)", rule.Destination)
			continue
		}

		egressRule := ciliumapi.EgressRule{
			EgressCommonRule: ciliumapi.EgressCommonRule{
				ToCIDR: cidrsList,
			},
		}

		switch rule.Protocol {
		case "tcp":
			egressRule.ToPorts = toPorts(rule.Ports, ciliumapi.ProtoTCP)
		case "udp":
			egressRule.ToPorts = toPorts(rule.Ports, ciliumapi.ProtoUDP)
		case "icmp":
			egressRule.ICMPs = icmpRule(rule.Type, ciliumapi.IPv4Family)
		case "icmpv6":
			egressRule.ICMPs = icmpRule(rule.Type, ciliumapi.IPv6Family)
		case "all":
			// do not set any ports or ICMPs to allow all protocols for given destinations
		default:
			// we need to continue for unsupported protocols to
			// avoid adding empty rules which would allow all traffic
			log.Printf("unsupported protocol %q (rule will be ignored)", rule.Protocol)
			continue
		}

		ciliumEgressRules = append(ciliumEgressRules, egressRule)
	}

	return ciliumEgressRules
}

func toPorts(portStr string, protocol ciliumapi.L4Proto) []ciliumapi.PortRule {
	if portStr == "" {
		portStr = "1-65535"
	}

	var portRules []ciliumapi.PortRule
	for _, port := range strings.Split(portStr, ",") {
		portRange := strings.SplitN(strings.TrimSpace(port), "-", 2)

		var (
			startPort string
			endPort   int64
			err       error
		)
		if len(portRange) == 2 {
			startPort = portRange[0]
			endPort, err = strconv.ParseInt(portRange[1], 10, 32)
			if err != nil {
				continue
			}
		} else {
			startPort = portRange[0]
			endPort, err = strconv.ParseInt(portRange[0], 10, 32)
			if err != nil {
				continue
			}
		}

		portRules = append(portRules, ciliumapi.PortRule{
			Ports: []ciliumapi.PortProtocol{{
				Port:     startPort,
				EndPort:  int32(endPort),
				Protocol: protocol,
			}},
		})
	}
	return portRules
}

func icmpRule(icmpType int, ipFamily ...string) ciliumapi.ICMPRules {
	rule := ciliumapi.ICMPRule{}

	for _, family := range ipFamily {
		if icmpType == -1 {
			for _, typeNum := range getIcmpTypes(family) {
				rule.Fields = append(rule.Fields, ciliumapi.ICMPField{
					Family: family,
					Type: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: typeNum,
					},
				})
			}
		} else {
			rule.Fields = append(rule.Fields, ciliumapi.ICMPField{
				Family: family,
				Type: &intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: int32(icmpType),
				},
			})
		}
	}

	return ciliumapi.ICMPRules{rule}
}

func getIcmpTypes(ipFamily string) []int32 {
	if ipFamily == ciliumapi.IPv4Family {
		return []int32{
			0,  // EchoReply
			3,  // DestinationUnreachable
			5,  // Redirect
			8,  // Echo/EchoRequest
			9,  // RouterAdvertisement
			10, // RouterSelection
			11, // TimeExceeded
			12, // ParameterProblem
			13, // Timestamp
			14, // TimestampReply
			40, // Photuris
			42, // ExtendedEchoRequest
			43, // ExtendedEchoReply
		}
	} else {
		// IPv6
		return []int32{
			1,   // DestinationUnreachable
			2,   // PacketTooBig
			3,   // TimeExceeded
			4,   // ParameterProblem
			128, // EchoRequest
			129, // EchoReply
			130, // MulticastListenerQuery
			131, // MulticastListenerReport
			132, // MulticastListenerDone
			133, // RouterSolicitation
			134, // RouterAdvertisement
			135, // NeighborSolicitation
			136, // NeighborAdvertisement
			137, // RedirectMessage
			138, // RouterRenumbering
			139, // ICMPNodeInformationQuery
			140, // ICMPNodeInformationResponse
			141, // InverseNeighborDiscoverySolicitation
			142, // InverseNeighborDiscoveryAdvertisement
			144, // HomeAgentAddressDiscoveryRequest
			145, // HomeAgentAddressDiscoveryReply
			146, // MobilePrefixSolicitation
			147, // MobilePrefixAdvertisement
			157, // DuplicateAddressRequestCodeSuffix
			158, // DuplicateAddressConfirmationCodeSuffix
			160, // ExtendedEchoRequest
			161, // ExtendedEchoReply
		}
	}
}

func translateToCidrs(destination string) ([]ciliumapi.CIDR, error) {
	if destination == "" {
		return nil, errors.New("empty destination")
	}

	if strings.Contains(destination, "/") {
		return []ciliumapi.CIDR{ciliumapi.CIDR(destination)}, nil
	}

	if strings.Contains(destination, "-") {
		return ipRangeToCIDRs(destination)
	}

	return []ciliumapi.CIDR{ciliumapi.CIDR(destination + "/32")}, nil
}

// converts an IP range (e.g., "169.255.0.0-172.15.255.255") to minimal set of CIDRs
func ipRangeToCIDRs(ipRange string) ([]ciliumapi.CIDR, error) {
	ranges, err := util.RangeToCIDRs(ipRange)
	if err != nil {
		return nil, err
	}

	cidrs := make([]ciliumapi.CIDR, len(ranges))
	for i, r := range ranges {
		cidrs[i] = ciliumapi.CIDR(r)
	}

	return cidrs, nil
}

// createCiliumEgressSelectorsFromASG creates an endpoint selector based on ASG metadata
func createCiliumEgressSelectorsFromASG(asg policy.SecurityGroup) []slimv1.LabelSelector {
	selectors := []slimv1.LabelSelector{}

	if asg.StagingDefault {
		selectors = append(selectors, slimv1.LabelSelector{
			MatchExpressions: []slimv1.LabelSelectorRequirement{{
				Key:      "cloudfoundry.org/source-type",
				Operator: slimv1.LabelSelectorOpIn,
				Values:   []string{"STG"},
			}},
		})
	}
	if asg.RunningDefault {
		selectors = append(selectors, slimv1.LabelSelector{
			MatchExpressions: []slimv1.LabelSelectorRequirement{{
				Key:      "cloudfoundry.org/source-type",
				Operator: slimv1.LabelSelectorOpNotIn,
				Values:   []string{"STG"},
			}},
		})
	}
	if len(asg.RunningSpaceGuids) > 0 {
		selectors = append(selectors, slimv1.LabelSelector{
			MatchExpressions: []slimv1.LabelSelectorRequirement{
				{
					Key:      "cloudfoundry.org/space-guid",
					Operator: slimv1.LabelSelectorOpIn,
					Values:   asg.RunningSpaceGuids,
				},
				{
					Key:      "cloudfoundry.org/source-type",
					Operator: slimv1.LabelSelectorOpNotIn,
					Values:   []string{"STG"},
				},
			},
		})
	}
	if len(asg.StagingSpaceGuids) > 0 {
		selectors = append(selectors, slimv1.LabelSelector{
			MatchExpressions: []slimv1.LabelSelectorRequirement{
				{
					Key:      "cloudfoundry.org/space-guid",
					Operator: slimv1.LabelSelectorOpIn,
					Values:   asg.StagingSpaceGuids,
				},
				{
					Key:      "cloudfoundry.org/source-type",
					Operator: slimv1.LabelSelectorOpIn,
					Values:   []string{"STG"},
				},
			},
		})
	}

	return selectors
}
