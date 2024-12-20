// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2-devel
// 	protoc        v5.28.3
// source: config/v1/config.proto

package configv1

import (
	_ "github.com/marnixbouhuis/confpb/pkg/gen/confpb/v1"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ApplicationConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Server *ApplicationConfig_ServerConfig `protobuf:"bytes,1,opt,name=server" json:"server,omitempty"`
	// Multiple values can be set for a list using:
	// - SOME_LIST_1 = "item1"
	// - SOME_LIST_2 = "item2"
	// - SOME_LIST_3 = "item3"
	// - SOME_LIST_4 = "item4"
	// ...
	SomeList []string `protobuf:"bytes,2,rep,name=some_list,json=someList" json:"some_list,omitempty"`
	// Multiple values can also be set for nested messages, the env key specified for the list will be used as prefix.
	// Values can be set using:
	// - SERVER_LIST_1_HOST = "1.2.3.4"
	// - SERVER_LIST_1_HOST = "8080"
	// - SERVER_LIST_2_HOST = "127.0.0.1"
	// - SERVER_LIST_2_HOST = "433"
	// ...
	ServerList []*ApplicationConfig_ServerConfig `protobuf:"bytes,3,rep,name=server_list,json=serverList" json:"server_list,omitempty"`
	// Some types have a special mapping. For durations, strings are parsed to durations (e.g. 10s, 10m30s, 1h).
	// Other types that use special parsing include: timestamps, structs, struct values, and fields with the "bytes" type.
	SomeDuration *durationpb.Duration `protobuf:"bytes,4,opt,name=some_duration,json=someDuration" json:"some_duration,omitempty"`
	KeyValue     map[string]string    `protobuf:"bytes,5,rep,name=key_value,json=keyValue" json:"key_value,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
}

func (x *ApplicationConfig) Reset() {
	*x = ApplicationConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_v1_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ApplicationConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApplicationConfig) ProtoMessage() {}

func (x *ApplicationConfig) ProtoReflect() protoreflect.Message {
	mi := &file_config_v1_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApplicationConfig.ProtoReflect.Descriptor instead.
func (*ApplicationConfig) Descriptor() ([]byte, []int) {
	return file_config_v1_config_proto_rawDescGZIP(), []int{0}
}

func (x *ApplicationConfig) GetServer() *ApplicationConfig_ServerConfig {
	if x != nil {
		return x.Server
	}
	return nil
}

func (x *ApplicationConfig) GetSomeList() []string {
	if x != nil {
		return x.SomeList
	}
	return nil
}

func (x *ApplicationConfig) GetServerList() []*ApplicationConfig_ServerConfig {
	if x != nil {
		return x.ServerList
	}
	return nil
}

func (x *ApplicationConfig) GetSomeDuration() *durationpb.Duration {
	if x != nil {
		return x.SomeDuration
	}
	return nil
}

func (x *ApplicationConfig) GetKeyValue() map[string]string {
	if x != nil {
		return x.KeyValue
	}
	return nil
}

type ApplicationConfig_ServerConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host *string `protobuf:"bytes,1,opt,name=host" json:"host,omitempty"`
	Port *uint32 `protobuf:"varint,2,opt,name=port" json:"port,omitempty"`
}

func (x *ApplicationConfig_ServerConfig) Reset() {
	*x = ApplicationConfig_ServerConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_v1_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ApplicationConfig_ServerConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ApplicationConfig_ServerConfig) ProtoMessage() {}

func (x *ApplicationConfig_ServerConfig) ProtoReflect() protoreflect.Message {
	mi := &file_config_v1_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ApplicationConfig_ServerConfig.ProtoReflect.Descriptor instead.
func (*ApplicationConfig_ServerConfig) Descriptor() ([]byte, []int) {
	return file_config_v1_config_proto_rawDescGZIP(), []int{0, 0}
}

func (x *ApplicationConfig_ServerConfig) GetHost() string {
	if x != nil && x.Host != nil {
		return *x.Host
	}
	return ""
}

func (x *ApplicationConfig_ServerConfig) GetPort() uint32 {
	if x != nil && x.Port != nil {
		return *x.Port
	}
	return 0
}

var File_config_v1_config_proto protoreflect.FileDescriptor

var file_config_v1_config_proto_rawDesc = []byte{
	0x0a, 0x16, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x76, 0x31, 0x2f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x76, 0x31, 0x1a, 0x15, 0x63, 0x6f, 0x6e, 0x66, 0x70, 0x62, 0x2f, 0x76, 0x31, 0x2f, 0x66,
	0x69, 0x65, 0x6c, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe0, 0x04, 0x0a, 0x11, 0x41,
	0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x12, 0x4c, 0x0a, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x29, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x70, 0x70,
	0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x53,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x42, 0x09, 0x92, 0x4e, 0x06,
	0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x52, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x12, 0x4d,
	0x0a, 0x09, 0x73, 0x6f, 0x6d, 0x65, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x02, 0x20, 0x03, 0x28,
	0x09, 0x42, 0x30, 0x92, 0x4e, 0x09, 0x53, 0x4f, 0x4d, 0x45, 0x5f, 0x4c, 0x49, 0x53, 0x54, 0x9a,
	0x4e, 0x21, 0x9a, 0x02, 0x1e, 0x0a, 0x08, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x31, 0x0a,
	0x08, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x32, 0x0a, 0x08, 0x64, 0x65, 0x66, 0x61, 0x75,
	0x6c, 0x74, 0x33, 0x52, 0x08, 0x73, 0x6f, 0x6d, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x5a, 0x0a,
	0x0b, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x03, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x29, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x76, 0x31, 0x2e, 0x41,
	0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x42, 0x0e, 0x92,
	0x4e, 0x0b, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x5f, 0x4c, 0x49, 0x53, 0x54, 0x52, 0x0a, 0x73,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x58, 0x0a, 0x0d, 0x73, 0x6f, 0x6d,
	0x65, 0x5f, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x18, 0x92, 0x4e, 0x0d,
	0x53, 0x4f, 0x4d, 0x45, 0x5f, 0x44, 0x55, 0x52, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x9a, 0x4e, 0x05,
	0x92, 0x01, 0x02, 0x32, 0x73, 0x52, 0x0c, 0x73, 0x6f, 0x6d, 0x65, 0x44, 0x75, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x71, 0x0a, 0x09, 0x6b, 0x65, 0x79, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e,
	0x76, 0x31, 0x2e, 0x41, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2e, 0x4b, 0x65, 0x79, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x42, 0x28, 0x9a, 0x4e, 0x25, 0xda, 0x02, 0x22, 0x0a, 0x0f, 0x62, 0x04, 0x6b, 0x65,
	0x79, 0x31, 0xd2, 0x01, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x31, 0x0a, 0x0f, 0x62, 0x04, 0x6b,
	0x65, 0x79, 0x32, 0xd2, 0x01, 0x06, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x32, 0x52, 0x08, 0x6b, 0x65,
	0x79, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x1a, 0x48, 0x0a, 0x0c, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x1b, 0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0x92, 0x4e, 0x04, 0x48, 0x4f, 0x53, 0x54, 0x52, 0x04, 0x68,
	0x6f, 0x73, 0x74, 0x12, 0x1b, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0d, 0x42, 0x07, 0x92, 0x4e, 0x04, 0x50, 0x4f, 0x52, 0x54, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74,
	0x1a, 0x3b, 0x0a, 0x0d, 0x4b, 0x65, 0x79, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03,
	0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x28, 0x5a,
	0x21, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2d, 0x61, 0x70, 0x70, 0x2f, 0x67, 0x65, 0x6e, 0x2f,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x76, 0x31, 0x3b, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x76, 0x31, 0x92, 0x03, 0x02, 0x08, 0x01, 0x62, 0x08, 0x65, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x70, 0xe8, 0x07,
}

var (
	file_config_v1_config_proto_rawDescOnce sync.Once
	file_config_v1_config_proto_rawDescData = file_config_v1_config_proto_rawDesc
)

func file_config_v1_config_proto_rawDescGZIP() []byte {
	file_config_v1_config_proto_rawDescOnce.Do(func() {
		file_config_v1_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_config_v1_config_proto_rawDescData)
	})
	return file_config_v1_config_proto_rawDescData
}

var file_config_v1_config_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_config_v1_config_proto_goTypes = []any{
	(*ApplicationConfig)(nil),              // 0: config.v1.ApplicationConfig
	(*ApplicationConfig_ServerConfig)(nil), // 1: config.v1.ApplicationConfig.ServerConfig
	nil,                                    // 2: config.v1.ApplicationConfig.KeyValueEntry
	(*durationpb.Duration)(nil),            // 3: google.protobuf.Duration
}
var file_config_v1_config_proto_depIdxs = []int32{
	1, // 0: config.v1.ApplicationConfig.server:type_name -> config.v1.ApplicationConfig.ServerConfig
	1, // 1: config.v1.ApplicationConfig.server_list:type_name -> config.v1.ApplicationConfig.ServerConfig
	3, // 2: config.v1.ApplicationConfig.some_duration:type_name -> google.protobuf.Duration
	2, // 3: config.v1.ApplicationConfig.key_value:type_name -> config.v1.ApplicationConfig.KeyValueEntry
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_config_v1_config_proto_init() }
func file_config_v1_config_proto_init() {
	if File_config_v1_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_config_v1_config_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*ApplicationConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_config_v1_config_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*ApplicationConfig_ServerConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_config_v1_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_config_v1_config_proto_goTypes,
		DependencyIndexes: file_config_v1_config_proto_depIdxs,
		MessageInfos:      file_config_v1_config_proto_msgTypes,
	}.Build()
	File_config_v1_config_proto = out.File
	file_config_v1_config_proto_rawDesc = nil
	file_config_v1_config_proto_goTypes = nil
	file_config_v1_config_proto_depIdxs = nil
}
