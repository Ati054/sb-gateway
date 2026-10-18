//go:build linux

package watchdog

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func nftAttributes(t *testing.T, attributes ...netlink.Attribute) []byte {
	t.Helper()
	data, err := netlink.MarshalAttributes(attributes)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestNativeNFTDecodesTProxyWithoutDroppingUnknownPositions(t *testing.T) {
	fixture := completeNFTReader().rules["prerouting"][0]
	var nested []netlink.Attribute
	for _, expression := range fixture.Exprs {
		data, err := expr.Marshal(byte(nftables.TableFamilyINet), expression)
		if err != nil {
			t.Fatal(err)
		}
		nested = append(nested, netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: data})
	}
	nested = append(nested, netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM,
		Data: nftAttributes(t, netlink.Attribute{Type: unix.NFTA_EXPR_NAME, Data: []byte("future-extension\x00")})})
	attributes := nftAttributes(t,
		netlink.Attribute{Type: unix.NFTA_RULE_TABLE, Data: []byte(transparentTable + "\x00")},
		netlink.Attribute{Type: unix.NFTA_RULE_CHAIN, Data: []byte("prerouting\x00")},
		netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_RULE_EXPRESSIONS, Data: nftAttributes(t, nested...)})
	message := netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWRULE)},
		Data: append([]byte{byte(nftables.TableFamilyINet), unix.NFNETLINK_V0, 0, 0}, attributes...)}
	rule, err := decodeNFTRule(message, nftables.TableFamilyINet)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Table.Name != transparentTable || rule.Chain.Name != "prerouting" || len(rule.Exprs) != 5 || rule.Exprs[4] != nil {
		t.Fatalf("incomplete or reordered rule: %+v", rule)
	}
	if protocol, routed := nativeTProxy(rule.Exprs, 12345); protocol != unix.IPPROTO_TCP || !routed {
		t.Fatal("TPROXY expression was lost on decode")
	}
	broken := append([]expr.Any{rule.Exprs[0], nil}, rule.Exprs[1:]...)
	if protocol, routed := nativeTProxy(broken, 12345); protocol != 0 || routed {
		t.Fatal("unknown expression joined an unrelated load and comparison")
	}
}

func TestNativeNFTRejectsMalformedMessages(t *testing.T) {
	typeCode := netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWRULE)
	for _, message := range []netlink.Message{
		{Header: netlink.Header{Type: typeCode}},
		{Header: netlink.Header{Type: netlink.Error}, Data: []byte{1, 0, 0, 0}},
		{Header: netlink.Header{Type: typeCode}, Data: []byte{byte(nftables.TableFamilyIPv4), 0, 0, 0}},
		{Header: netlink.Header{Type: typeCode}, Data: []byte{byte(nftables.TableFamilyINet), 9, 0, 0}},
		{Header: netlink.Header{Type: typeCode}, Data: []byte{byte(nftables.TableFamilyINet), 0, 0, 0, 255, 0, 1, 0}},
	} {
		if _, err := decodeNFTRule(message, nftables.TableFamilyINet); err == nil {
			t.Fatal("malformed netlink message accepted")
		}
	}
	badProxy := nftAttributes(t, netlink.Attribute{Type: expr.NFTA_TPROXY_REG_PORT, Data: []byte{1}})
	badExpression := nftAttributes(t,
		netlink.Attribute{Type: unix.NFTA_EXPR_NAME, Data: []byte("tproxy\x00")},
		netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: badProxy})
	list := nftAttributes(t, netlink.Attribute{Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: badExpression})
	if _, err := decodeNFTExpressions(list, byte(nftables.TableFamilyINet)); err == nil {
		t.Fatal("invalid TPROXY register width accepted")
	}
}

func FuzzNativeNFTDecoders(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{255, 0, 1, 0})
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeNFTExpressions(data, byte(nftables.TableFamilyINet))
		_, _ = decodeNFTRule(netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWRULE)}, Data: data}, nftables.TableFamilyINet)
	})
}
