package netpolicy

import (
	"net"
	"testing"
)

// Assert effective Go configuration without requiring a particular host kernel
// or an MPTCP-capable network socket.
func TestTCPListenConfigOverridesAmbientMultipath(t *testing.T) {
	for _, setting := range []string{"multipathtcp=1", "disablethp=1", "disablethp=1,multipathtcp=0"} {
		t.Run(setting, func(t *testing.T) {
			t.Setenv("GODEBUG", setting)
			config := TCPListenConfig()
			if config.MultipathTCP() {
				t.Fatal("gateway TCP listener inherited ambient MPTCP")
			}
		})
	}
}

func TestCompiledMultipathDefaultSurvivesLegacyEnvironment(t *testing.T) {
	for _, setting := range []string{"", "disablethp=1"} {
		t.Run(setting, func(t *testing.T) {
			t.Setenv("GODEBUG", setting)
			var config net.ListenConfig
			if config.MultipathTCP() {
				t.Fatal("compiled MPTCP default was lost when the environment omitted it")
			}
		})
	}
}

func TestExplicitMultipathOptInRemainsPossible(t *testing.T) {
	t.Setenv("GODEBUG", "multipathtcp=0")
	var config net.ListenConfig
	config.SetMultipathTCP(true)
	if !config.MultipathTCP() {
		t.Fatal("compiled/process default suppressed an explicit MPTCP opt-in")
	}
}

func TestListenTCPRejectsOtherSocketFamilies(t *testing.T) {
	for _, network := range []string{"udp", "udp4", "udp6", "unix", "unixgram"} {
		if listener, err := ListenTCP(network, ""); err == nil || listener != nil {
			t.Fatalf("%s escaped the TCP-only listener boundary", network)
		}
	}
}
