package agent

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Wire projections of the pinned Xray API, without linking its proxy engines.
// One monitor-owned connection is shared by all isolated probe runtimes.
type xrayControlClient struct {
	conn     *grpc.ClientConn
	messages protoreflect.MessageDescriptors
}

const xrayControlRPCTimeout = 3 * time.Second

func newXrayControlClient(address string) (*xrayControlClient, error) {
	optional, repeated := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	stringType, messageType := descriptorpb.FieldDescriptorProto_TYPE_STRING, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	integerType := descriptorpb.FieldDescriptorProto_TYPE_INT64
	field := func(name string, number int32, nested string, list bool) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(number), Label: &optional, Type: &stringType}
		if nested != "" {
			f.Type, f.TypeName = &messageType, proto.String(".sb.gateway.xray.control."+nested)
		}
		if list {
			f.Label = &repeated
		}
		return f
	}
	message := func(name string, fields ...*descriptorpb.FieldDescriptorProto) *descriptorpb.DescriptorProto {
		return &descriptorpb.DescriptorProto{Name: proto.String(name), Field: fields}
	}
	statValue := field("value", 2, "", false)
	statValue.Type = &integerType
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("sb-xray-control.proto"), Package: proto.String("sb.gateway.xray.control"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			message("GetBalancerInfoRequest", field("tag", 1, "", false)),
			message("OverrideInfo", field("target", 2, "", false)),
			message("BalancerInfo", field("override", 5, "OverrideInfo", false)),
			message("GetBalancerInfoResponse", field("balancer", 1, "BalancerInfo", false)),
			message("OverrideBalancerTargetRequest", field("balancerTag", 1, "", false), field("target", 2, "", false)),
			message("OverrideBalancerTargetResponse"),
			message("OutboundTag", field("tag", 1, "", false)),
			message("ListOutboundsRequest"),
			message("ListOutboundsResponse", field("outbounds", 1, "OutboundTag", true)),
			message("RemoveOutboundRequest", field("tag", 1, "", false)),
			message("RemoveOutboundResponse"),
			message("GetStatsRequest", field("name", 1, "", false)),
			message("Stat", field("name", 1, "", false), statValue),
			message("GetStatsResponse", field("stat", 1, "Stat", false)),
		},
	}, nil)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &xrayControlClient{conn: conn, messages: file.Messages()}, nil
}

func (client *xrayControlClient) close() { _ = client.conn.Close() }

func (client *xrayControlClient) message(name string) *dynamicpb.Message {
	return dynamicpb.NewMessage(client.messages.ByName(protoreflect.Name(name)))
}

func (client *xrayControlClient) invoke(parent context.Context, operation, service, method string, request, response *dynamicpb.Message) (err error) {
	slot, lane := xrayCommandSlot, "active"
	if parent.Value(backgroundXrayCommandKey{}) == true {
		slot, lane = xrayProbeCommandSlots, "background"
	}
	trace := beginHealthStage("api", lane, "", "")
	trace.command(operation)
	defer func() { trace.finishError(err, parent.Err() != nil) }()
	select {
	case slot <- struct{}{}:
		defer func() { <-slot }()
		trace.acquiredSlot()
	case <-parent.Done():
		return parent.Err()
	}
	ctx, cancel := context.WithTimeout(parent, xrayControlRPCTimeout)
	defer cancel()
	err = client.conn.Invoke(ctx, "/xray.app."+service+".command."+method, request, response)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if status.Code(err) == codes.DeadlineExceeded {
		return errors.Join(err, context.DeadlineExceeded)
	}
	return err
}

func setControlString(message *dynamicpb.Message, name, value string) {
	message.Set(message.Descriptor().Fields().ByName(protoreflect.Name(name)), protoreflect.ValueOfString(value))
}

func (client *xrayControlClient) selected(parent context.Context, selector string) (string, error) {
	request, response := client.message("GetBalancerInfoRequest"), client.message("GetBalancerInfoResponse")
	setControlString(request, "tag", selector)
	if err := client.invoke(parent, "bi", "router", "RoutingService/GetBalancerInfo", request, response); err != nil {
		return "", err
	}
	field := response.Descriptor().Fields().ByName("balancer")
	if !response.Has(field) {
		return "", errors.New("Xray balancer response is missing")
	}
	balancer := response.Get(field).Message()
	override := balancer.Descriptor().Fields().ByName("override")
	if !balancer.Has(override) {
		return "", nil
	}
	value := balancer.Get(override).Message()
	return value.Get(value.Descriptor().Fields().ByName("target")).String(), nil
}

func (client *xrayControlClient) override(parent context.Context, selector, target string) error {
	request, response := client.message("OverrideBalancerTargetRequest"), client.message("OverrideBalancerTargetResponse")
	setControlString(request, "balancerTag", selector)
	setControlString(request, "target", target)
	return client.invoke(parent, "bo", "router", "RoutingService/OverrideBalancerTarget", request, response)
}

func (client *xrayControlClient) outbounds(parent context.Context) (map[string]bool, error) {
	request, response := client.message("ListOutboundsRequest"), client.message("ListOutboundsResponse")
	if err := client.invoke(parent, "lso", "proxyman", "HandlerService/ListOutbounds", request, response); err != nil {
		return nil, err
	}
	list := response.Get(response.Descriptor().Fields().ByName("outbounds")).List()
	tags := make(map[string]bool, list.Len())
	for i := 0; i < list.Len(); i++ {
		item := list.Get(i).Message()
		tag := item.Get(item.Descriptor().Fields().ByName("tag")).String()
		if tag == "" || tags[tag] {
			return nil, errors.New("Xray outbound inventory is invalid")
		}
		tags[tag] = true
	}
	return tags, nil
}

func (client *xrayControlClient) remove(parent context.Context, tag string) error {
	request, response := client.message("RemoveOutboundRequest"), client.message("RemoveOutboundResponse")
	setControlString(request, "tag", tag)
	return client.invoke(parent, "rmo", "proxyman", "HandlerService/RemoveOutbound", request, response)
}

func (client *xrayControlClient) online(parent context.Context, candidate string) (bool, error) {
	request, response := client.message("GetStatsRequest"), client.message("GetStatsResponse")
	name := "user>>>" + candidate + ">>>online"
	setControlString(request, "name", name)
	if err := client.invoke(parent, "statsonline", "stats", "StatsService/GetStatsOnline", request, response); err != nil {
		return false, err
	}
	field := response.Descriptor().Fields().ByName("stat")
	if !response.Has(field) {
		return false, errors.New("Xray online statistic is missing")
	}
	stat := response.Get(field).Message()
	actual := stat.Get(stat.Descriptor().Fields().ByName("name")).String()
	if actual != name {
		return false, errors.New("Xray online statistic name differs")
	}
	return stat.Get(stat.Descriptor().Fields().ByName("value")).Int() > 0, nil
}
