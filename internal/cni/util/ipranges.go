package util

import (
	"fmt"
	"math/bits"
	"net"
	"strings"
)

// rangeToCIDRs converts an IP range (as uint32) to minimal set of CIDRs
// This uses an efficient algorithm that finds the largest aligned CIDR block
// that fits at the start of the range, then recursively processes the remainder
func RangeToCIDRs(ipRange string) ([]string, error) {
	var cidrs []string

	start, end, err := parseRange(ipRange)
	if err != nil {
		return nil, err
	}

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
		cidrs = append(cidrs, fmt.Sprintf("%s/%d", uint32ToIP(start).String(), prefixLen))

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

	return cidrs, nil
}

// ipToUint32 converts an IPv4 address to a 32-bit unsigned integer
func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIP converts a 32-bit unsigned integer to an IPv4 address
func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func parseRange(ipRange string) (uint32, uint32, error) {
	parts := strings.SplitN(ipRange, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid IP range format: %s", ipRange)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	if startIP == nil || endIP == nil {
		return 0, 0, fmt.Errorf("invalid IP addresses in range: %s", ipRange)
	}

	startIP = startIP.To4()
	endIP = endIP.To4()

	if startIP == nil || endIP == nil {
		return 0, 0, fmt.Errorf("only IPv4 ranges are supported: %s", ipRange)
	}

	startInt := ipToUint32(startIP)
	endInt := ipToUint32(endIP)

	if startInt > endInt {
		return 0, 0, fmt.Errorf("start IP is greater than end IP: %s", ipRange)
	}

	return startInt, endInt, nil
}
