// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: grpc/grpc_empty.proto

package testing

import (
	context "context"
	fmt "fmt"
	grpc1 "github.com/gogo/protobuf/grpc"
	proto "github.com/gogo/protobuf/proto"
	grpc "google.golang.org/grpc"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

func init() { proto.RegisterFile("grpc/grpc_empty.proto", fileDescriptor_c580a37f1c90e9b1) }

var fileDescriptor_c580a37f1c90e9b1 = []byte{
	// 121 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0x4d, 0x2f, 0x2a, 0x48,
	0xd6, 0x07, 0x11, 0xf1, 0xa9, 0xb9, 0x05, 0x25, 0x95, 0x7a, 0x05, 0x45, 0xf9, 0x25, 0xf9, 0x42,
	0x3c, 0x20, 0x11, 0xbd, 0x92, 0xd4, 0xe2, 0x92, 0xcc, 0xbc, 0x74, 0x23, 0x3e, 0x2e, 0x1e, 0x57,
	0x90, 0x64, 0x70, 0x6a, 0x51, 0x59, 0x66, 0x72, 0xaa, 0x93, 0x43, 0x94, 0x5d, 0x7a, 0x66, 0x49,
	0x46, 0x69, 0x92, 0x5e, 0x72, 0x7e, 0xae, 0x7e, 0x7a, 0x7e, 0x7a, 0xbe, 0x3e, 0x58, 0x5b, 0x52,
	0x69, 0x1a, 0x84, 0x91, 0xac, 0x9b, 0x9e, 0x9a, 0xa7, 0x0b, 0x96, 0x00, 0x99, 0x91, 0x92, 0x58,
	0x92, 0x08, 0xb6, 0xc3, 0x1a, 0x6a, 0x62, 0x12, 0x1b, 0x58, 0x99, 0x31, 0x20, 0x00, 0x00, 0xff,
	0xff, 0x15, 0xf0, 0x09, 0x1e, 0x7f, 0x00, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// EmptyServiceClient is the client API for EmptyService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type EmptyServiceClient interface {
}

type emptyServiceClient struct {
	cc grpc1.ClientConn
}

func NewEmptyServiceClient(cc ClientConn) EmptyServiceClient {
	return &emptyServiceClient{cc}
}

// EmptyServiceServer is the server API for EmptyService service.
type EmptyServiceServer interface {
}

// UnimplementedEmptyServiceServer can be embedded to have forward compatible implementations.
type UnimplementedEmptyServiceServer struct {
}

func RegisterEmptyServiceServer(s grpc1.Server, srv EmptyServiceServer) {
	s.RegisterService(&_EmptyService_serviceDesc, srv)
}

var _EmptyService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "grpc.testing.EmptyService",
	HandlerType: (*EmptyServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams:     []grpc.StreamDesc{},
	Metadata:    "grpc/grpc_empty.proto",
}
