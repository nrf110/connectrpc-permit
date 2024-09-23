// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: nrf110/permit/v1/permit.proto

package warrantv1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	descriptorpb "google.golang.org/protobuf/types/descriptorpb"
	_ "google.golang.org/protobuf/types/known/anypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type CheckMode int32

const (
	CheckMode_all_of CheckMode = 0
	CheckMode_any_of CheckMode = 1
)

// Enum value maps for CheckMode.
var (
	CheckMode_name = map[int32]string{
		0: "all_of",
		1: "any_of",
	}
	CheckMode_value = map[string]int32{
		"all_of": 0,
		"any_of": 1,
	}
)

func (x CheckMode) Enum() *CheckMode {
	p := new(CheckMode)
	*p = x
	return p
}

func (x CheckMode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (CheckMode) Descriptor() protoreflect.EnumDescriptor {
	return file_nrf110_permit_v1_permit_proto_enumTypes[0].Descriptor()
}

func (CheckMode) Type() protoreflect.EnumType {
	return &file_nrf110_permit_v1_permit_proto_enumTypes[0]
}

func (x CheckMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use CheckMode.Descriptor instead.
func (CheckMode) EnumDescriptor() ([]byte, []int) {
	return file_nrf110_permit_v1_permit_proto_rawDescGZIP(), []int{0}
}

type ResourceOptions struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type     string `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	Relation string `protobuf:"bytes,2,opt,name=relation,proto3" json:"relation,omitempty"`
}

func (x *ResourceOptions) Reset() {
	*x = ResourceOptions{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nrf110_permit_v1_permit_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceOptions) ProtoMessage() {}

func (x *ResourceOptions) ProtoReflect() protoreflect.Message {
	mi := &file_nrf110_permit_v1_permit_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceOptions.ProtoReflect.Descriptor instead.
func (*ResourceOptions) Descriptor() ([]byte, []int) {
	return file_nrf110_permit_v1_permit_proto_rawDescGZIP(), []int{0}
}

func (x *ResourceOptions) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *ResourceOptions) GetRelation() string {
	if x != nil {
		return x.Relation
	}
	return ""
}

type CheckOptions struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Bulk     bool      `protobuf:"varint,1,opt,name=bulk,proto3" json:"bulk,omitempty"`
	CrossOrg bool      `protobuf:"varint,2,opt,name=cross_org,json=crossOrg,proto3" json:"cross_org,omitempty"`
	Mode     CheckMode `protobuf:"varint,3,opt,name=mode,proto3,enum=nrf110.warrant.v1.CheckMode" json:"mode,omitempty"`
}

func (x *CheckOptions) Reset() {
	*x = CheckOptions{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nrf110_permit_v1_permit_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CheckOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CheckOptions) ProtoMessage() {}

func (x *CheckOptions) ProtoReflect() protoreflect.Message {
	mi := &file_nrf110_permit_v1_permit_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CheckOptions.ProtoReflect.Descriptor instead.
func (*CheckOptions) Descriptor() ([]byte, []int) {
	return file_nrf110_permit_v1_permit_proto_rawDescGZIP(), []int{1}
}

func (x *CheckOptions) GetBulk() bool {
	if x != nil {
		return x.Bulk
	}
	return false
}

func (x *CheckOptions) GetCrossOrg() bool {
	if x != nil {
		return x.CrossOrg
	}
	return false
}

func (x *CheckOptions) GetMode() CheckMode {
	if x != nil {
		return x.Mode
	}
	return CheckMode_all_of
}

var file_nrf110_permit_v1_permit_proto_extTypes = []protoimpl.ExtensionInfo{
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         3000,
		Name:          "nrf110.warrant.v1.resources",
		Tag:           "varint,3000,opt,name=resources",
		Filename:      "nrf110/permit/v1/permit.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         3001,
		Name:          "nrf110.warrant.v1.resource_id",
		Tag:           "varint,3001,opt,name=resource_id",
		Filename:      "nrf110/permit/v1/permit.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         3002,
		Name:          "nrf110.warrant.v1.tenant_id",
		Tag:           "varint,3002,opt,name=tenant_id",
		Filename:      "nrf110/permit/v1/permit.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*string)(nil),
		Field:         3003,
		Name:          "nrf110.warrant.v1.attribute_name",
		Tag:           "bytes,3003,opt,name=attribute_name",
		Filename:      "nrf110/permit/v1/permit.proto",
	},
	{
		ExtendedType:  (*descriptorpb.MessageOptions)(nil),
		ExtensionType: (*ResourceOptions)(nil),
		Field:         3000,
		Name:          "nrf110.warrant.v1.resource",
		Tag:           "bytes,3000,opt,name=resource",
		Filename:      "nrf110/permit/v1/permit.proto",
	},
	{
		ExtendedType:  (*descriptorpb.MessageOptions)(nil),
		ExtensionType: (*CheckOptions)(nil),
		Field:         3200,
		Name:          "nrf110.warrant.v1.check",
		Tag:           "bytes,3200,opt,name=check",
		Filename:      "nrf110/permit/v1/permit.proto",
	},
}

// Extension fields to descriptorpb.FieldOptions.
var (
	// marks this field as a collection of resources
	//
	// optional bool resources = 3000;
	E_Resources = &file_nrf110_permit_v1_permit_proto_extTypes[0]
	// optional bool resource_id = 3001;
	E_ResourceId = &file_nrf110_permit_v1_permit_proto_extTypes[1]
	// optional bool tenant_id = 3002;
	E_TenantId = &file_nrf110_permit_v1_permit_proto_extTypes[2]
	// optional string attribute_name = 3003;
	E_AttributeName = &file_nrf110_permit_v1_permit_proto_extTypes[3]
)

// Extension fields to descriptorpb.MessageOptions.
var (
	// optional nrf110.warrant.v1.ResourceOptions resource = 3000;
	E_Resource = &file_nrf110_permit_v1_permit_proto_extTypes[4]
	// optional nrf110.warrant.v1.CheckOptions check = 3200;
	E_Check = &file_nrf110_permit_v1_permit_proto_extTypes[5]
)

var File_nrf110_permit_v1_permit_proto protoreflect.FileDescriptor

var file_nrf110_permit_v1_permit_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x6e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2f, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x2f,
	0x76, 0x31, 0x2f, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x11, 0x6e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2e, 0x77, 0x61, 0x72, 0x72, 0x61, 0x6e, 0x74, 0x2e,
	0x76, 0x31, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x20, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64,
	0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x41, 0x0a, 0x0f, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x22, 0x71, 0x0a, 0x0c, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x4f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x62, 0x75, 0x6c, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x04, 0x62, 0x75, 0x6c, 0x6b, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x5f,
	0x6f, 0x72, 0x67, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x63, 0x72, 0x6f, 0x73, 0x73,
	0x4f, 0x72, 0x67, 0x12, 0x30, 0x0a, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x1c, 0x2e, 0x6e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2e, 0x77, 0x61, 0x72, 0x72, 0x61,
	0x6e, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x4d, 0x6f, 0x64, 0x65, 0x52,
	0x04, 0x6d, 0x6f, 0x64, 0x65, 0x2a, 0x23, 0x0a, 0x09, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x4d, 0x6f,
	0x64, 0x65, 0x12, 0x0a, 0x0a, 0x06, 0x61, 0x6c, 0x6c, 0x5f, 0x6f, 0x66, 0x10, 0x00, 0x12, 0x0a,
	0x0a, 0x06, 0x61, 0x6e, 0x79, 0x5f, 0x6f, 0x66, 0x10, 0x01, 0x3a, 0x3f, 0x0a, 0x09, 0x72, 0x65,
	0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xb8, 0x17, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x88, 0x01, 0x01, 0x3a, 0x42, 0x0a, 0x0b, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65,
	0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xb9, 0x17, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x0a, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x64, 0x88, 0x01, 0x01, 0x3a,
	0x3e, 0x0a, 0x09, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x12, 0x1d, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46,
	0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xba, 0x17, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x08, 0x74, 0x65, 0x6e, 0x61, 0x6e, 0x74, 0x49, 0x64, 0x88, 0x01, 0x01, 0x3a,
	0x48, 0x0a, 0x0e, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x5f, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x18, 0xbb, 0x17, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x88, 0x01, 0x01, 0x3a, 0x63, 0x0a, 0x08, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x1f, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x4f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xb8, 0x17, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e,
	0x6e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2e, 0x77, 0x61, 0x72, 0x72, 0x61, 0x6e, 0x74, 0x2e, 0x76,
	0x31, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x52, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x88, 0x01, 0x01, 0x3a, 0x5a,
	0x0a, 0x05, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x12, 0x1f, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x80, 0x19, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1f, 0x2e, 0x6e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2e, 0x77, 0x61, 0x72, 0x72, 0x61, 0x6e, 0x74,
	0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x52, 0x05, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x88, 0x01, 0x01, 0x42, 0xce, 0x01, 0x0a, 0x15, 0x63,
	0x6f, 0x6d, 0x2e, 0x6e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2e, 0x77, 0x61, 0x72, 0x72, 0x61, 0x6e,
	0x74, 0x2e, 0x76, 0x31, 0x42, 0x0b, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x50, 0x72, 0x6f, 0x74,
	0x6f, 0x50, 0x01, 0x5a, 0x42, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x6e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x72, 0x70,
	0x63, 0x2d, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x6e, 0x72, 0x66,
	0x31, 0x31, 0x30, 0x2f, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x2f, 0x76, 0x31, 0x3b, 0x77, 0x61,
	0x72, 0x72, 0x61, 0x6e, 0x74, 0x76, 0x31, 0xa2, 0x02, 0x03, 0x4e, 0x57, 0x58, 0xaa, 0x02, 0x11,
	0x4e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2e, 0x57, 0x61, 0x72, 0x72, 0x61, 0x6e, 0x74, 0x2e, 0x56,
	0x31, 0xca, 0x02, 0x11, 0x4e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x5c, 0x57, 0x61, 0x72, 0x72, 0x61,
	0x6e, 0x74, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x1d, 0x4e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x5c, 0x57,
	0x61, 0x72, 0x72, 0x61, 0x6e, 0x74, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0xea, 0x02, 0x13, 0x4e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x3a, 0x3a,
	0x57, 0x61, 0x72, 0x72, 0x61, 0x6e, 0x74, 0x3a, 0x3a, 0x56, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_nrf110_permit_v1_permit_proto_rawDescOnce sync.Once
	file_nrf110_permit_v1_permit_proto_rawDescData = file_nrf110_permit_v1_permit_proto_rawDesc
)

func file_nrf110_permit_v1_permit_proto_rawDescGZIP() []byte {
	file_nrf110_permit_v1_permit_proto_rawDescOnce.Do(func() {
		file_nrf110_permit_v1_permit_proto_rawDescData = protoimpl.X.CompressGZIP(file_nrf110_permit_v1_permit_proto_rawDescData)
	})
	return file_nrf110_permit_v1_permit_proto_rawDescData
}

var file_nrf110_permit_v1_permit_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_nrf110_permit_v1_permit_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_nrf110_permit_v1_permit_proto_goTypes = []any{
	(CheckMode)(0),                      // 0: nrf110.warrant.v1.CheckMode
	(*ResourceOptions)(nil),             // 1: nrf110.warrant.v1.ResourceOptions
	(*CheckOptions)(nil),                // 2: nrf110.warrant.v1.CheckOptions
	(*descriptorpb.FieldOptions)(nil),   // 3: google.protobuf.FieldOptions
	(*descriptorpb.MessageOptions)(nil), // 4: google.protobuf.MessageOptions
}
var file_nrf110_permit_v1_permit_proto_depIdxs = []int32{
	0, // 0: nrf110.warrant.v1.CheckOptions.mode:type_name -> nrf110.warrant.v1.CheckMode
	3, // 1: nrf110.warrant.v1.resources:extendee -> google.protobuf.FieldOptions
	3, // 2: nrf110.warrant.v1.resource_id:extendee -> google.protobuf.FieldOptions
	3, // 3: nrf110.warrant.v1.tenant_id:extendee -> google.protobuf.FieldOptions
	3, // 4: nrf110.warrant.v1.attribute_name:extendee -> google.protobuf.FieldOptions
	4, // 5: nrf110.warrant.v1.resource:extendee -> google.protobuf.MessageOptions
	4, // 6: nrf110.warrant.v1.check:extendee -> google.protobuf.MessageOptions
	1, // 7: nrf110.warrant.v1.resource:type_name -> nrf110.warrant.v1.ResourceOptions
	2, // 8: nrf110.warrant.v1.check:type_name -> nrf110.warrant.v1.CheckOptions
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	7, // [7:9] is the sub-list for extension type_name
	1, // [1:7] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_nrf110_permit_v1_permit_proto_init() }
func file_nrf110_permit_v1_permit_proto_init() {
	if File_nrf110_permit_v1_permit_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_nrf110_permit_v1_permit_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*ResourceOptions); i {
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
		file_nrf110_permit_v1_permit_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*CheckOptions); i {
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
			RawDescriptor: file_nrf110_permit_v1_permit_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   2,
			NumExtensions: 6,
			NumServices:   0,
		},
		GoTypes:           file_nrf110_permit_v1_permit_proto_goTypes,
		DependencyIndexes: file_nrf110_permit_v1_permit_proto_depIdxs,
		EnumInfos:         file_nrf110_permit_v1_permit_proto_enumTypes,
		MessageInfos:      file_nrf110_permit_v1_permit_proto_msgTypes,
		ExtensionInfos:    file_nrf110_permit_v1_permit_proto_extTypes,
	}.Build()
	File_nrf110_permit_v1_permit_proto = out.File
	file_nrf110_permit_v1_permit_proto_rawDesc = nil
	file_nrf110_permit_v1_permit_proto_goTypes = nil
	file_nrf110_permit_v1_permit_proto_depIdxs = nil
}
