//go:build !xray_multicall

package domainset

const nativeMatcherName = "map"

func compileMembership(exact, suffix []membership) (membershipMatcher, error) {
	return compileMapMembership(exact, suffix), nil
}
