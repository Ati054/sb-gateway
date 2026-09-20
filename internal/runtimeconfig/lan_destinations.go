package runtimeconfig

// trustedFullIPv4Destinations is intentionally limited to RFC1918 address
// space. A trusted-full remote user may follow RouterOS route changes without
// re-applying the appliance, while public and carrier-grade ranges remain
// governed by the explicit configured network inventory.
var trustedFullIPv4Destinations = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}
