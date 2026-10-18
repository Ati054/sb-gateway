//go:build linux

package watchdog

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strconv"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const transparentTable = "sb_gateway_transparent"

type nftReader interface {
	ListChain(*nftables.Table, string) (*nftables.Chain, error)
	GetRules(*nftables.Table, *nftables.Chain) ([]*nftables.Rule, error)
}

type nftSocket interface {
	SetDeadline(time.Time) error
	Close() error
}

func bindNFTContext(ctx context.Context, socket nftSocket) (func() bool, error) {
	deadline, _ := ctx.Deadline()
	if err := socket.SetDeadline(deadline); err != nil {
		_ = socket.Close()
		return nil, err
	}
	return context.AfterFunc(ctx, func() { _ = socket.Close() }), nil
}

func probeTransparentNFT(parent context.Context, port string) (bool, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	var stop func() bool
	var socket *netlink.Conn
	connection, err := nftables.New(nftables.AsLasting(), nftables.WithSockOptions(func(opened *netlink.Conn) error {
		socket = opened
		var err error
		stop, err = bindNFTContext(ctx, opened)
		return err
	}))
	if err != nil {
		return false, errors.Join(err, ctx.Err())
	}
	defer connection.CloseLasting()
	defer stop()
	valid, err := readTransparentNFT(kernelNFTReader{Conn: connection, socket: socket}, port)
	if err != nil {
		return false, errors.Join(err, ctx.Err())
	}
	return valid, nil
}

// Read only the two managed chains; never dump unrelated tables or modify rules.
func readTransparentNFT(reader nftReader, port string) (bool, error) {
	target, err := strconv.Atoi(port)
	if err != nil || target < 1 || target > 65535 {
		return false, nil
	}
	table := &nftables.Table{Name: transparentTable, Family: nftables.TableFamilyINet}
	var tcp, udp, guard bool
	for _, expected := range []struct {
		name string
		hook *nftables.ChainHook
	}{{"prerouting", nftables.ChainHookPrerouting}, {"forward", nftables.ChainHookForward}} {
		chain, err := reader.ListChain(table, expected.name)
		if err != nil {
			return false, err
		}
		if !managedNFTChain(chain, expected.name, expected.hook) {
			return false, nil
		}
		rules, err := reader.GetRules(table, chain)
		if err != nil {
			return false, err
		}
		for _, rule := range rules {
			if rule == nil || rule.Table == nil || rule.Chain == nil ||
				rule.Table.Name != table.Name || rule.Table.Family != table.Family || rule.Chain.Name != chain.Name {
				continue
			}
			if expected.name == "prerouting" {
				protocol, routed := nativeTProxy(rule.Exprs, uint16(target))
				tcp = tcp || routed && protocol == unix.IPPROTO_TCP
				udp = udp || routed && protocol == unix.IPPROTO_UDP
			} else {
				guard = guard || nativeTransitGuard(rule)
			}
		}
	}
	return tcp && udp && guard, nil
}

func managedNFTChain(chain *nftables.Chain, name string, hook *nftables.ChainHook) bool {
	return chain != nil && chain.Table != nil && chain.Table.Name == transparentTable &&
		chain.Table.Family == nftables.TableFamilyINet && chain.Name == name &&
		chain.Type == nftables.ChainTypeFilter && chain.Hooknum != nil && *chain.Hooknum == *hook
}

func metaEquality(expressions []expr.Any, index int, key expr.MetaKey) ([]byte, bool) {
	meta, ok := expressions[index].(*expr.Meta)
	if !ok || meta.SourceRegister || meta.Key != key || index+1 >= len(expressions) {
		return nil, false
	}
	compare, ok := expressions[index+1].(*expr.Cmp)
	if !ok || compare.Op != expr.CmpOpEq || compare.Register != meta.Register {
		return nil, false
	}
	return compare.Data, true
}

func nativeTProxy(expressions []expr.Any, target uint16) (byte, bool) {
	var protocol byte
	for index, item := range expressions {
		if data, ok := metaEquality(expressions, index, expr.MetaKeyL4PROTO); ok && len(data) == 1 {
			protocol = data[0]
		}
		proxy, ok := item.(*expr.TProxy)
		if !ok || index == 0 {
			continue
		}
		value, ok := expressions[index-1].(*expr.Immediate)
		if ok && value.Register == proxy.RegPort && len(value.Data) == 2 && binary.BigEndian.Uint16(value.Data) == target &&
			(protocol == unix.IPPROTO_TCP || protocol == unix.IPPROTO_UDP) {
			return protocol, true
		}
	}
	return 0, false
}

func nativeTransitGuard(rule *nftables.Rule) bool {
	// The upstream userdata helper expects structurally valid TLVs.
	for rest := rule.UserData; len(rest) > 0; {
		if len(rest) < 2 || int(rest[1])+2 > len(rest) {
			return false
		}
		rest = rest[int(rest[1])+2:]
	}
	comment, ok := userdata.GetString(rule.UserData, userdata.TypeComment)
	if !ok || comment != "sb-public-transit-reject" {
		return false
	}
	var ingress, reject bool
	for index, item := range rule.Exprs {
		if data, ok := metaEquality(rule.Exprs, index, expr.MetaKeyIIFNAME); ok {
			name, suffix, terminated := bytes.Cut(data, []byte{0})
			ingress = len(name) > 0 && len(data) <= unix.IFNAMSIZ && terminated && len(bytes.Trim(suffix, "\x00")) == 0
		}
		if action, ok := item.(*expr.Reject); ok {
			reject = reject || action.Type == unix.NFT_REJECT_ICMPX_UNREACH && action.Code == unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED
		}
	}
	return ingress && reject
}
