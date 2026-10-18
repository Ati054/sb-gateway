//go:build linux

package watchdog

import (
	"encoding/binary"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type kernelNFTReader struct {
	*nftables.Conn
	socket *netlink.Conn
}

// nftables v0.3.0 silently omits TProxy when decoding rules. Use its typed
// expressions with the netlink attribute decoder, retaining that expression.
func (reader kernelNFTReader) GetRules(table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error) {
	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: append([]byte(table.Name), 0)},
		{Type: unix.NFTA_RULE_CHAIN, Data: append([]byte(chain.Name), 0)},
	})
	if err != nil {
		return nil, err
	}
	messages, err := reader.socket.Execute(netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETRULE), Flags: netlink.Request | netlink.Dump},
		Data:   append([]byte{byte(table.Family), unix.NFNETLINK_V0, 0, 0}, attributes...),
	})
	if err != nil {
		return nil, err
	}
	rules := make([]*nftables.Rule, 0, len(messages))
	for _, message := range messages {
		rule, err := decodeNFTRule(message, table.Family)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func decodeNFTRule(message netlink.Message, family nftables.TableFamily) (*nftables.Rule, error) {
	if message.Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWRULE) ||
		len(message.Data) < 4 || message.Data[0] != byte(family) || message.Data[1] != unix.NFNETLINK_V0 {
		return nil, fmt.Errorf("invalid nft rule envelope")
	}
	attributes, err := netlink.NewAttributeDecoder(message.Data[4:])
	if err != nil {
		return nil, err
	}
	rule := &nftables.Rule{}
	for attributes.Next() {
		switch attributes.Type() {
		case unix.NFTA_RULE_TABLE:
			rule.Table = &nftables.Table{Name: attributes.String(), Family: family}
		case unix.NFTA_RULE_CHAIN:
			rule.Chain = &nftables.Chain{Name: attributes.String()}
		case unix.NFTA_RULE_USERDATA:
			rule.UserData = attributes.Bytes()
		case unix.NFTA_RULE_EXPRESSIONS:
			attributes.Do(func(data []byte) error {
				var err error
				rule.Exprs, err = decodeNFTExpressions(data, byte(family))
				return err
			})
		}
	}
	return rule, attributes.Err()
}

func decodeNFTExpressions(data []byte, family byte) ([]expr.Any, error) {
	list, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return nil, err
	}
	var expressions []expr.Any
	for list.Next() {
		if list.Type() != unix.NFTA_LIST_ELEM {
			return nil, fmt.Errorf("invalid nft expression list")
		}
		list.Do(func(data []byte) error {
			attributes, err := netlink.NewAttributeDecoder(data)
			if err != nil {
				return err
			}
			var name string
			var body []byte
			for attributes.Next() {
				switch attributes.Type() {
				case unix.NFTA_EXPR_NAME:
					name = attributes.String()
				case unix.NFTA_EXPR_DATA:
					body = attributes.Bytes()
				}
			}
			if err := attributes.Err(); err != nil {
				return err
			}
			var expression expr.Any
			switch name {
			case "meta":
				expression = &expr.Meta{}
			case "cmp":
				expression = &expr.Cmp{}
			case "immediate":
				expression = &expr.Immediate{}
			case "reject":
				expression = &expr.Reject{}
			case "tproxy":
				proxy := &expr.TProxy{TableFamily: family}
				attributes, err := netlink.NewAttributeDecoder(body)
				if err != nil {
					return err
				}
				attributes.ByteOrder = binary.BigEndian
				for attributes.Next() {
					switch attributes.Type() {
					case expr.NFTA_TPROXY_FAMILY:
						proxy.Family = byte(attributes.Uint32())
					case expr.NFTA_TPROXY_REG_ADDR:
						proxy.RegAddr = attributes.Uint32()
					case expr.NFTA_TPROXY_REG_PORT:
						proxy.RegPort = attributes.Uint32()
					}
				}
				if err := attributes.Err(); err != nil {
					return err
				}
				expressions = append(expressions, proxy)
				return nil
			}
			if expression != nil {
				if err := expr.Unmarshal(family, body, expression); err != nil {
					return err
				}
			}
			// Preserve an unknown expression's position; do not join unrelated
			// register loads and comparisons across it.
			expressions = append(expressions, expression)
			return nil
		})
	}
	return expressions, list.Err()
}
