//go:build linux

package watchdog

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"
)

type fakeNFTReader struct {
	chains map[string]*nftables.Chain
	rules  map[string][]*nftables.Rule
	err    error
	reads  int
}

func (reader *fakeNFTReader) ListChain(table *nftables.Table, name string) (*nftables.Chain, error) {
	reader.reads++
	if table.Name != transparentTable || table.Family != nftables.TableFamilyINet {
		panic("read of unrelated nft table")
	}
	return reader.chains[name], reader.err
}

func (reader *fakeNFTReader) GetRules(table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error) {
	reader.reads++
	if table.Name != transparentTable || (chain.Name != "prerouting" && chain.Name != "forward") {
		panic("read of unrelated nft chain")
	}
	return reader.rules[chain.Name], reader.err
}

func completeNFTReader() *fakeNFTReader {
	table := &nftables.Table{Name: transparentTable, Family: nftables.TableFamilyINet}
	pre := &nftables.Chain{Name: "prerouting", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting}
	forward := &nftables.Chain{Name: "forward", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward}
	proxy := func(protocol byte) *nftables.Rule {
		return &nftables.Rule{Table: table, Chain: pre, Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocol}},
			&expr.Immediate{Register: 1, Data: []byte{0x30, 0x39}},
			&expr.TProxy{RegPort: 1},
		}}
	}
	guard := &nftables.Rule{Table: table, Chain: forward,
		UserData: userdata.AppendString(nil, userdata.TypeComment, "sb-public-transit-reject"),
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: append([]byte("veth-sb"), 0)},
			&expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED},
		}}
	return &fakeNFTReader{chains: map[string]*nftables.Chain{"prerouting": pre, "forward": forward},
		rules: map[string][]*nftables.Rule{"prerouting": {proxy(unix.IPPROTO_TCP), proxy(unix.IPPROTO_UDP)}, "forward": {guard}}}
}

func TestNativeNFTReadOnlyCompleteProof(t *testing.T) {
	reader := completeNFTReader()
	if valid, err := readTransparentNFT(reader, "12345"); err != nil || !valid || reader.reads != 4 {
		t.Fatalf("complete proof rejected or unbounded inventory: valid=%v reads=%d err=%v", valid, reader.reads, err)
	}
}

func TestNativeNFTRejectsIncompleteOrUnrelatedProof(t *testing.T) {
	for name, change := range map[string]func(*fakeNFTReader){
		"missing chain":           func(r *fakeNFTReader) { delete(r.chains, "forward") },
		"wrong hook":              func(r *fakeNFTReader) { r.chains["forward"].Hooknum = nftables.ChainHookInput },
		"wrong type":              func(r *fakeNFTReader) { r.chains["prerouting"].Type = nftables.ChainTypeNAT },
		"wrong family":            func(r *fakeNFTReader) { r.chains["prerouting"].Table.Family = nftables.TableFamilyIPv4 },
		"wrong table":             func(r *fakeNFTReader) { r.chains["forward"].Table.Name = "other" },
		"no udp":                  func(r *fakeNFTReader) { r.rules["prerouting"] = r.rules["prerouting"][:1] },
		"wrong port":              func(r *fakeNFTReader) { r.rules["prerouting"][0].Exprs[2].(*expr.Immediate).Data = []byte{0, 80} },
		"wrong port register":     func(r *fakeNFTReader) { r.rules["prerouting"][0].Exprs[3].(*expr.TProxy).RegPort = 2 },
		"wrong protocol register": func(r *fakeNFTReader) { r.rules["prerouting"][0].Exprs[1].(*expr.Cmp).Register = 2 },
		"not equal protocol":      func(r *fakeNFTReader) { r.rules["prerouting"][0].Exprs[1].(*expr.Cmp).Op = expr.CmpOpNeq },
		"source meta":             func(r *fakeNFTReader) { r.rules["prerouting"][0].Exprs[0].(*expr.Meta).SourceRegister = true },
		"no guard":                func(r *fakeNFTReader) { r.rules["forward"] = nil },
		"wrong comment": func(r *fakeNFTReader) {
			r.rules["forward"][0].UserData = userdata.AppendString(nil, userdata.TypeComment, "other")
		},
		"malformed userdata":     func(r *fakeNFTReader) { r.rules["forward"][0].UserData = []byte{0, 255} },
		"empty ingress":          func(r *fakeNFTReader) { r.rules["forward"][0].Exprs[1].(*expr.Cmp).Data = []byte{0} },
		"wrong ingress register": func(r *fakeNFTReader) { r.rules["forward"][0].Exprs[1].(*expr.Cmp).Register = 2 },
		"wrong reject": func(r *fakeNFTReader) {
			r.rules["forward"][0].Exprs[2].(*expr.Reject).Code = unix.NFT_REJECT_ICMPX_NO_ROUTE
		},
		"wrong rule chain": func(r *fakeNFTReader) { r.rules["forward"][0].Chain = &nftables.Chain{Name: "input"} },
		"nil rule":         func(r *fakeNFTReader) { r.rules["forward"] = []*nftables.Rule{nil} },
	} {
		t.Run(name, func(t *testing.T) {
			reader := completeNFTReader()
			change(reader)
			if valid, err := readTransparentNFT(reader, "12345"); valid || err != nil {
				t.Fatalf("invalid proof accepted or confused with read error: %v, %v", valid, err)
			}
		})
	}
	for _, port := range []string{"", "-1", "0", "65536", "x"} {
		reader := completeNFTReader()
		if valid, err := readTransparentNFT(reader, port); valid || err != nil || reader.reads != 0 {
			t.Fatalf("invalid target port %q triggered inventory", port)
		}
	}
}

func TestNativeNFTReadErrorAndCancellation(t *testing.T) {
	reader := completeNFTReader()
	reader.err = errors.New("read failed")
	if valid, err := readTransparentNFT(reader, "12345"); valid || !errors.Is(err, reader.err) {
		t.Fatal("lost read failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if valid, err := probeTransparentNFT(ctx, "12345"); valid || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled probe read kernel state")
	}
}

type fakeNFTSocket struct {
	deadline time.Time
	closed   chan struct{}
	err      error
}

func (socket *fakeNFTSocket) SetDeadline(deadline time.Time) error {
	socket.deadline = deadline
	return socket.err
}

func (socket *fakeNFTSocket) Close() error {
	close(socket.closed)
	return nil
}

func TestNativeNFTCancellationClosesSocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	socket := &fakeNFTSocket{closed: make(chan struct{})}
	stop, err := bindNFTContext(ctx, socket)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	deadline, _ := ctx.Deadline()
	if !socket.deadline.Equal(deadline) {
		t.Fatal("socket lost the aggregate deadline")
	}
	cancel()
	select {
	case <-socket.closed:
	case <-time.After(time.Second):
		t.Fatal("cancelled read retained a socket")
	}

	failed := &fakeNFTSocket{closed: make(chan struct{}), err: errors.New("deadline unavailable")}
	if stop, err := bindNFTContext(context.Background(), failed); stop != nil || !errors.Is(err, failed.err) {
		t.Fatal("deadline setup failure was ignored")
	}
	select {
	case <-failed.closed:
	default:
		t.Fatal("deadline setup failure leaked the socket")
	}
}

func TestNativeNFTIsolatedKernel(t *testing.T) {
	if os.Getenv("SB_WATCHDOG_NETLINK_INTEGRATION") != "1" {
		t.Skip("requires root, unshare and nft in an isolated test namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "unshare", "--net", os.Args[0], "-test.run=^TestNativeNFTKernelHelper$", "--", "nft-kernel-helper").CombinedOutput()
	if err != nil {
		t.Fatalf("isolated native nft proof failed: %v\n%s", err, output)
	}
}

func TestNativeNFTKernelHelper(t *testing.T) {
	if os.Args[len(os.Args)-1] != "nft-kernel-helper" {
		return
	}
	load := func(source string) {
		t.Helper()
		command := exec.Command("nft", "-f", "-")
		command.Stdin = strings.NewReader(source)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated fixture: %v\n%s", err, output)
		}
	}
	load(`table inet sb_gateway_transparent {
 chain prerouting {
  type filter hook prerouting priority mangle; policy accept;
  meta l4proto tcp tproxy to :12345
  meta l4proto udp tproxy to :12345
 }
 chain forward {
  type filter hook forward priority filter; policy accept;
  iifname "veth-sb" reject with icmpx type admin-prohibited comment "sb-public-transit-reject"
 }
}`)
	if valid, err := probeTransparentNFT(context.Background(), "12345"); err != nil || !valid {
		reader, openErr := nftables.New()
		if openErr != nil {
			t.Fatal(openErr)
		}
		table := &nftables.Table{Name: transparentTable, Family: nftables.TableFamilyINet}
		for _, name := range []string{"prerouting", "forward"} {
			chain, readErr := reader.ListChain(table, name)
			t.Logf("chain=%+v error=%v", chain, readErr)
			rules, readErr := reader.GetRules(table, &nftables.Chain{Name: name})
			t.Logf("rules error=%v", readErr)
			for _, rule := range rules {
				t.Logf("rule=%+v", rule)
				for _, expression := range rule.Exprs {
					t.Logf("expr=%T %+v", expression, expression)
				}
			}
		}
		t.Fatalf("real kernel proof rejected: %v, %v", valid, err)
	}
	if valid, err := probeTransparentNFT(context.Background(), "12346"); err != nil || valid {
		t.Fatalf("wrong port accepted: %v, %v", valid, err)
	}
	load("flush chain inet sb_gateway_transparent forward")
	if valid, err := probeTransparentNFT(context.Background(), "12345"); err != nil || valid {
		t.Fatalf("missing real guard accepted: %v, %v", valid, err)
	}
}
