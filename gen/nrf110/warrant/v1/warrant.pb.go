// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: nrf110/warrant/v1/warrant.proto

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
	return file_nrf110_warrant_v1_warrant_proto_enumTypes[0].Descriptor()
}

func (CheckMode) Type() protoreflect.EnumType {
	return &file_nrf110_warrant_v1_warrant_proto_enumTypes[0]
}

func (x CheckMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use CheckMode.Descriptor instead.
func (CheckMode) EnumDescriptor() ([]byte, []int) {
	return file_nrf110_warrant_v1_warrant_proto_rawDescGZIP(), []int{0}
}

type SubjectOptions struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type     string  `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	IdClaim  *string `protobuf:"bytes,2,opt,name=id_claim,json=idClaim,proto3,oneof" json:"id_claim,omitempty"`
	Relation *string `protobuf:"bytes,3,opt,name=relation,proto3,oneof" json:"relation,omitempty"`
}

func (x *SubjectOptions) Reset() {
	*x = SubjectOptions{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nrf110_warrant_v1_warrant_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubjectOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubjectOptions) ProtoMessage() {}

func (x *SubjectOptions) ProtoReflect() protoreflect.Message {
	mi := &file_nrf110_warrant_v1_warrant_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubjectOptions.ProtoReflect.Descriptor instead.
func (*SubjectOptions) Descriptor() ([]byte, []int) {
	return file_nrf110_warrant_v1_warrant_proto_rawDescGZIP(), []int{0}
}

func (x *SubjectOptions) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *SubjectOptions) GetIdClaim() string {
	if x != nil && x.IdClaim != nil {
		return *x.IdClaim
	}
	return ""
}

func (x *SubjectOptions) GetRelation() string {
	if x != nil && x.Relation != nil {
		return *x.Relation
	}
	return ""
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
		mi := &file_nrf110_warrant_v1_warrant_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceOptions) ProtoMessage() {}

func (x *ResourceOptions) ProtoReflect() protoreflect.Message {
	mi := &file_nrf110_warrant_v1_warrant_proto_msgTypes[1]
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
	return file_nrf110_warrant_v1_warrant_proto_rawDescGZIP(), []int{1}
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

var file_nrf110_warrant_v1_warrant_proto_extTypes = []protoimpl.ExtensionInfo{
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         3000,
		Name:          "nrf110.warrant.v1.resources",
		Tag:           "varint,3000,opt,name=resources",
		Filename:      "nrf110/warrant/v1/warrant.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         3001,
		Name:          "nrf110.warrant.v1.resource_id",
		Tag:           "varint,3001,opt,name=resource_id",
		Filename:      "nrf110/warrant/v1/warrant.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         3002,
		Name:          "nrf110.warrant.v1.org_id",
		Tag:           "varint,3002,opt,name=org_id",
		Filename:      "nrf110/warrant/v1/warrant.proto",
	},
	{
		ExtendedType:  (*descriptorpb.FieldOptions)(nil),
		ExtensionType: (*string)(nil),
		Field:         3003,
		Name:          "nrf110.warrant.v1.meta_name",
		Tag:           "bytes,3003,opt,name=meta_name",
		Filename:      "nrf110/warrant/v1/warrant.proto",
	},
	{
		ExtendedType:  (*descriptorpb.MethodOptions)(nil),
		ExtensionType: (*ResourceOptions)(nil),
		Field:         3000,
		Name:          "nrf110.warrant.v1.resource",
		Tag:           "bytes,3000,opt,name=resource",
		Filename:      "nrf110/warrant/v1/warrant.proto",
	},
	{
		ExtendedType:  (*descriptorpb.MethodOptions)(nil),
		ExtensionType: (*SubjectOptions)(nil),
		Field:         3100,
		Name:          "nrf110.warrant.v1.subject",
		Tag:           "bytes,3100,opt,name=subject",
		Filename:      "nrf110/warrant/v1/warrant.proto",
	},
	{
		ExtendedType:  (*descriptorpb.MethodOptions)(nil),
		ExtensionType: (*CheckMode)(nil),
		Field:         3200,
		Name:          "nrf110.warrant.v1.check_mode",
		Tag:           "varint,3200,opt,name=check_mode,enum=nrf110.warrant.v1.CheckMode",
		Filename:      "nrf110/warrant/v1/warrant.proto",
	},
	{
		ExtendedType:  (*descriptorpb.MethodOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         3201,
		Name:          "nrf110.warrant.v1.cross_org",
		Tag:           "varint,3201,opt,name=cross_org",
		Filename:      "nrf110/warrant/v1/warrant.proto",
	},
	{
		ExtendedType:  (*descriptorpb.MethodOptions)(nil),
		ExtensionType: (*bool)(nil),
		Field:         3202,
		Name:          "nrf110.warrant.v1.bulk",
		Tag:           "varint,3202,opt,name=bulk",
		Filename:      "nrf110/warrant/v1/warrant.proto",
	},
}

// Extension fields to descriptorpb.FieldOptions.
var (
	// marks this field as a
	//
	// optional bool resources = 3000;
	E_Resources = &file_nrf110_warrant_v1_warrant_proto_extTypes[0]
	// optional bool resource_id = 3001;
	E_ResourceId = &file_nrf110_warrant_v1_warrant_proto_extTypes[1]
	// optional bool org_id = 3002;
	E_OrgId = &file_nrf110_warrant_v1_warrant_proto_extTypes[2]
	// optional string meta_name = 3003;
	E_MetaName = &file_nrf110_warrant_v1_warrant_proto_extTypes[3]
)

// Extension fields to descriptorpb.MethodOptions.
var (
	// optional nrf110.warrant.v1.ResourceOptions resource = 3000;
	E_Resource = &file_nrf110_warrant_v1_warrant_proto_extTypes[4]
	// optional nrf110.warrant.v1.SubjectOptions subject = 3100;
	E_Subject = &file_nrf110_warrant_v1_warrant_proto_extTypes[5]
	// optional nrf110.warrant.v1.CheckMode check_mode = 3200;
	E_CheckMode = &file_nrf110_warrant_v1_warrant_proto_extTypes[6]
	// optional bool cross_org = 3201;
	E_CrossOrg = &file_nrf110_warrant_v1_warrant_proto_extTypes[7]
	// optional bool bulk = 3202;
	E_Bulk = &file_nrf110_warrant_v1_warrant_proto_extTypes[8]
)

var File_nrf110_warrant_v1_warrant_proto protoreflect.FileDescriptor

var file_nrf110_warrant_v1_warrant_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x6e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2f, 0x77, 0x61, 0x72, 0x72, 0x61, 0x6e, 0x74,
	0x2f, 0x76, 0x31, 0x2f, 0x77, 0x61, 0x72, 0x72, 0x61, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x11, 0x6e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2e, 0x77, 0x61, 0x72, 0x72, 0x61, 0x6e,
	0x74, 0x2e, 0x76, 0x31, 0x1a, 0x19, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x20, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x7f, 0x0a, 0x0e, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4f, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x1e, 0x0a, 0x08, 0x69, 0x64, 0x5f, 0x63, 0x6c,
	0x61, 0x69, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x07, 0x69, 0x64, 0x43,
	0x6c, 0x61, 0x69, 0x6d, 0x88, 0x01, 0x01, 0x12, 0x1f, 0x0a, 0x08, 0x72, 0x65, 0x6c, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x01, 0x52, 0x08, 0x72, 0x65, 0x6c,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x88, 0x01, 0x01, 0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x69, 0x64, 0x5f,
	0x63, 0x6c, 0x61, 0x69, 0x6d, 0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x22, 0x41, 0x0a, 0x0f, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4f, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x72, 0x65, 0x6c,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x72, 0x65, 0x6c,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2a, 0x23, 0x0a, 0x09, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x4d, 0x6f,
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
	0x38, 0x0a, 0x06, 0x6f, 0x72, 0x67, 0x5f, 0x69, 0x64, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c,
	0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xba, 0x17, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x05, 0x6f, 0x72, 0x67, 0x49, 0x64, 0x88, 0x01, 0x01, 0x3a, 0x3e, 0x0a, 0x09, 0x6d, 0x65, 0x74,
	0x61, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4f, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xbb, 0x17, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6d, 0x65,
	0x74, 0x61, 0x4e, 0x61, 0x6d, 0x65, 0x88, 0x01, 0x01, 0x3a, 0x62, 0x0a, 0x08, 0x72, 0x65, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x1e, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x4f, 0x70,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0xb8, 0x17, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x6e,
	0x72, 0x66, 0x31, 0x31, 0x30, 0x2e, 0x77, 0x61, 0x72, 0x72, 0x61, 0x6e, 0x74, 0x2e, 0x76, 0x31,
	0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x52, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x88, 0x01, 0x01, 0x3a, 0x5f, 0x0a,
	0x07, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x12, 0x1e, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4d, 0x65, 0x74, 0x68, 0x6f,
	0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x9c, 0x18, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x21, 0x2e, 0x6e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2e, 0x77, 0x61, 0x72, 0x72, 0x61, 0x6e, 0x74,
	0x2e, 0x76, 0x31, 0x2e, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x52, 0x07, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x88, 0x01, 0x01, 0x3a, 0x5f,
	0x0a, 0x0a, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x12, 0x1e, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4d,
	0x65, 0x74, 0x68, 0x6f, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x80, 0x19, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x1c, 0x2e, 0x6e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2e, 0x77, 0x61, 0x72,
	0x72, 0x61, 0x6e, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x4d, 0x6f, 0x64,
	0x65, 0x52, 0x09, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x4d, 0x6f, 0x64, 0x65, 0x88, 0x01, 0x01, 0x3a,
	0x3f, 0x0a, 0x09, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x5f, 0x6f, 0x72, 0x67, 0x12, 0x1e, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4d,
	0x65, 0x74, 0x68, 0x6f, 0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x81, 0x19, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x08, 0x63, 0x72, 0x6f, 0x73, 0x73, 0x4f, 0x72, 0x67, 0x88, 0x01, 0x01,
	0x3a, 0x36, 0x0a, 0x04, 0x62, 0x75, 0x6c, 0x6b, 0x12, 0x1e, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4d, 0x65, 0x74, 0x68, 0x6f,
	0x64, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x82, 0x19, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x04, 0x62, 0x75, 0x6c, 0x6b, 0x88, 0x01, 0x01, 0x42, 0xd0, 0x01, 0x0a, 0x15, 0x63, 0x6f, 0x6d,
	0x2e, 0x6e, 0x72, 0x66, 0x31, 0x31, 0x30, 0x2e, 0x77, 0x61, 0x72, 0x72, 0x61, 0x6e, 0x74, 0x2e,
	0x76, 0x31, 0x42, 0x0c, 0x57, 0x61, 0x72, 0x72, 0x61, 0x6e, 0x74, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x50, 0x01, 0x5a, 0x43, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6e,
	0x72, 0x66, 0x31, 0x31, 0x30, 0x2f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x72, 0x70, 0x63,
	0x2d, 0x77, 0x6f, 0x72, 0x6b, 0x6f, 0x73, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x6e, 0x72, 0x66, 0x31,
	0x31, 0x30, 0x2f, 0x77, 0x61, 0x72, 0x72, 0x61, 0x6e, 0x74, 0x2f, 0x76, 0x31, 0x3b, 0x77, 0x61,
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
	file_nrf110_warrant_v1_warrant_proto_rawDescOnce sync.Once
	file_nrf110_warrant_v1_warrant_proto_rawDescData = file_nrf110_warrant_v1_warrant_proto_rawDesc
)

func file_nrf110_warrant_v1_warrant_proto_rawDescGZIP() []byte {
	file_nrf110_warrant_v1_warrant_proto_rawDescOnce.Do(func() {
		file_nrf110_warrant_v1_warrant_proto_rawDescData = protoimpl.X.CompressGZIP(file_nrf110_warrant_v1_warrant_proto_rawDescData)
	})
	return file_nrf110_warrant_v1_warrant_proto_rawDescData
}

var file_nrf110_warrant_v1_warrant_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_nrf110_warrant_v1_warrant_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_nrf110_warrant_v1_warrant_proto_goTypes = []any{
	(CheckMode)(0),                     // 0: nrf110.warrant.v1.CheckMode
	(*SubjectOptions)(nil),             // 1: nrf110.warrant.v1.SubjectOptions
	(*ResourceOptions)(nil),            // 2: nrf110.warrant.v1.ResourceOptions
	(*descriptorpb.FieldOptions)(nil),  // 3: google.protobuf.FieldOptions
	(*descriptorpb.MethodOptions)(nil), // 4: google.protobuf.MethodOptions
}
var file_nrf110_warrant_v1_warrant_proto_depIdxs = []int32{
	3,  // 0: nrf110.warrant.v1.resources:extendee -> google.protobuf.FieldOptions
	3,  // 1: nrf110.warrant.v1.resource_id:extendee -> google.protobuf.FieldOptions
	3,  // 2: nrf110.warrant.v1.org_id:extendee -> google.protobuf.FieldOptions
	3,  // 3: nrf110.warrant.v1.meta_name:extendee -> google.protobuf.FieldOptions
	4,  // 4: nrf110.warrant.v1.resource:extendee -> google.protobuf.MethodOptions
	4,  // 5: nrf110.warrant.v1.subject:extendee -> google.protobuf.MethodOptions
	4,  // 6: nrf110.warrant.v1.check_mode:extendee -> google.protobuf.MethodOptions
	4,  // 7: nrf110.warrant.v1.cross_org:extendee -> google.protobuf.MethodOptions
	4,  // 8: nrf110.warrant.v1.bulk:extendee -> google.protobuf.MethodOptions
	2,  // 9: nrf110.warrant.v1.resource:type_name -> nrf110.warrant.v1.ResourceOptions
	1,  // 10: nrf110.warrant.v1.subject:type_name -> nrf110.warrant.v1.SubjectOptions
	0,  // 11: nrf110.warrant.v1.check_mode:type_name -> nrf110.warrant.v1.CheckMode
	12, // [12:12] is the sub-list for method output_type
	12, // [12:12] is the sub-list for method input_type
	9,  // [9:12] is the sub-list for extension type_name
	0,  // [0:9] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_nrf110_warrant_v1_warrant_proto_init() }
func file_nrf110_warrant_v1_warrant_proto_init() {
	if File_nrf110_warrant_v1_warrant_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_nrf110_warrant_v1_warrant_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*SubjectOptions); i {
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
		file_nrf110_warrant_v1_warrant_proto_msgTypes[1].Exporter = func(v any, i int) any {
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
	}
	file_nrf110_warrant_v1_warrant_proto_msgTypes[0].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_nrf110_warrant_v1_warrant_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   2,
			NumExtensions: 9,
			NumServices:   0,
		},
		GoTypes:           file_nrf110_warrant_v1_warrant_proto_goTypes,
		DependencyIndexes: file_nrf110_warrant_v1_warrant_proto_depIdxs,
		EnumInfos:         file_nrf110_warrant_v1_warrant_proto_enumTypes,
		MessageInfos:      file_nrf110_warrant_v1_warrant_proto_msgTypes,
		ExtensionInfos:    file_nrf110_warrant_v1_warrant_proto_extTypes,
	}.Build()
	File_nrf110_warrant_v1_warrant_proto = out.File
	file_nrf110_warrant_v1_warrant_proto_rawDesc = nil
	file_nrf110_warrant_v1_warrant_proto_goTypes = nil
	file_nrf110_warrant_v1_warrant_proto_depIdxs = nil
}
