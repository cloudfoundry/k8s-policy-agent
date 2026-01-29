package reconciler

import (
	"errors"
	"fmt"
	"log"
	"math/bits"
	"net"
	"strconv"
	"strings"

	policy "code.cloudfoundry.org/policy_client"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func CreateCiliumEgressRulesFromASG(asgRules []policy.SecurityGroupRule) []ciliumapi.EgressRule {
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
			endPort   int
			err       error
		)
		if len(portRange) == 2 {
			startPort = portRange[0]
			endPort, err = strconv.Atoi(portRange[1])
			if err != nil {
				continue
			}

		} else {
			startPort = portRange[0]
			endPort, err = strconv.Atoi(portRange[0])
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
			for _, typeNum := range GetIcmpTypes(family) {
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

func GetIcmpTypes(ipFamily string) []int32 {
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
	parts := strings.SplitN(ipRange, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format: %s", ipRange)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP addresses in range: %s", ipRange)
	}

	startIP = startIP.To4()
	endIP = endIP.To4()

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("only IPv4 ranges are supported: %s", ipRange)
	}

	startInt := ipToUint32(startIP)
	endInt := ipToUint32(endIP)

	if startInt > endInt {
		return nil, fmt.Errorf("start IP is greater than end IP: %s", ipRange)
	}

	return rangeToCIDRs(startInt, endInt), nil
}

// ipToUint32 converts an IPv4 address to a 32-bit unsigned integer
func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIP converts a 32-bit unsigned integer to an IPv4 address
func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// rangeToCIDRs converts an IP range (as uint32) to minimal set of CIDRs
// This uses an efficient algorithm that finds the largest aligned CIDR block
// that fits at the start of the range, then recursively processes the remainder
func rangeToCIDRs(start, end uint32) []ciliumapi.CIDR {
	var cidrs []ciliumapi.CIDR

	for start <= end {
		// Find the maximum prefix length where start is aligned
		// (i.e., how many trailing zeros in the binary representation)
		maxPrefixLen := 32
		if start != 0 {
			maxPrefixLen = bits.TrailingZeros32(start)
		}

		// Calculate how many IPs we can cover from start to end
		// Use uint64 to avoid overflow when end=0xFFFFFFFF and start=0
		rangeSize := uint64(end) - uint64(start) + 1

		// Find the largest CIDR block (smallest prefix) that:
		// 1. Is aligned with start (respects maxPrefixLen)
		// 2. Doesn't exceed the remaining range
		prefixLen := 32
		for p := maxPrefixLen; p >= 0; p-- {
			blockSize := uint64(1) << p
			if blockSize <= rangeSize {
				prefixLen = 32 - p
				break
			}
		}

		// Create CIDR notation
		cidr := ciliumapi.CIDR(fmt.Sprintf("%s/%d", uint32ToIP(start).String(), prefixLen))
		cidrs = append(cidrs, cidr)

		// if prefixLen is 0, we've covered the entire address space
		if prefixLen == 0 {
			break
		}

		// Move to the next block
		blockSize := uint32(1) << (32 - prefixLen)
		if start > 0xFFFFFFFF-blockSize {
			// Prevent overflow
			break
		}
		start += blockSize
	}

	return cidrs
}

// CreateCiliumEgressSelectorFromASG creates an endpoint selector based on ASG metadata
func CreateCiliumEgressSelectorsFromASG(asg policy.SecurityGroup) []slimv1.LabelSelector {
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
