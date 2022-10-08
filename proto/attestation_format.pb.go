// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.21.6
// source: attestation_format.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AttestationFormat int32

const (
	// UnknownFormat is used to indicate that the format of the attestation could
	// not be established.
	AttestationFormat_UNKNOWN_FORMAT AttestationFormat = 0
	// PSA_IOT is the PSA attestation format (based on:
	// https://developer.arm.com/architectures/architecture-security-features/platform-security)
	AttestationFormat_PSA_IOT AttestationFormat = 1
	// TCP_DICE is the attestation format based on the TCG DICE specification
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG_DICE_Attestation_Architecture_r22_02dec2020.pdf
	AttestationFormat_TCG_DICE AttestationFormat = 2
	// TPM EnactTrust
	AttestationFormat_TPM_ENACTTRUST AttestationFormat = 3
	// AWS Nitro Enclaves
	AttestationFormat_AWS_NITRO AttestationFormat = 4
)

// Enum value maps for AttestationFormat.
var (
	AttestationFormat_name = map[int32]string{
		0: "UNKNOWN_FORMAT",
		1: "PSA_IOT",
		2: "TCG_DICE",
		3: "TPM_ENACTTRUST",
		4: "AWS_NITRO",
	}
	AttestationFormat_value = map[string]int32{
		"UNKNOWN_FORMAT": 0,
		"PSA_IOT":        1,
		"TCG_DICE":       2,
		"TPM_ENACTTRUST": 3,
		"AWS_NITRO":      4,
	}
)

func (x AttestationFormat) Enum() *AttestationFormat {
	p := new(AttestationFormat)
	*p = x
	return p
}

func (x AttestationFormat) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (AttestationFormat) Descriptor() protoreflect.EnumDescriptor {
	return file_attestation_format_proto_enumTypes[0].Descriptor()
}

func (AttestationFormat) Type() protoreflect.EnumType {
	return &file_attestation_format_proto_enumTypes[0]
}

func (x AttestationFormat) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use AttestationFormat.Descriptor instead.
func (AttestationFormat) EnumDescriptor() ([]byte, []int) {
	return file_attestation_format_proto_rawDescGZIP(), []int{0}
}

var File_attestation_format_proto protoreflect.FileDescriptor

var file_attestation_format_proto_rawDesc = []byte{
	0x0a, 0x18, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x66, 0x6f,
	0x72, 0x6d, 0x61, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2a, 0x65, 0x0a, 0x11, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x12, 0x12, 0x0a, 0x0e, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57,
	0x4e, 0x5f, 0x46, 0x4f, 0x52, 0x4d, 0x41, 0x54, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x50, 0x53,
	0x41, 0x5f, 0x49, 0x4f, 0x54, 0x10, 0x01, 0x12, 0x0c, 0x0a, 0x08, 0x54, 0x43, 0x47, 0x5f, 0x44,
	0x49, 0x43, 0x45, 0x10, 0x02, 0x12, 0x12, 0x0a, 0x0e, 0x54, 0x50, 0x4d, 0x5f, 0x45, 0x4e, 0x41,
	0x43, 0x54, 0x54, 0x52, 0x55, 0x53, 0x54, 0x10, 0x03, 0x12, 0x0d, 0x0a, 0x09, 0x41, 0x57, 0x53,
	0x5f, 0x4e, 0x49, 0x54, 0x52, 0x4f, 0x10, 0x04, 0x42, 0x24, 0x5a, 0x22, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x76, 0x65, 0x72, 0x61, 0x69, 0x73, 0x6f, 0x6e, 0x2f,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_attestation_format_proto_rawDescOnce sync.Once
	file_attestation_format_proto_rawDescData = file_attestation_format_proto_rawDesc
)

func file_attestation_format_proto_rawDescGZIP() []byte {
	file_attestation_format_proto_rawDescOnce.Do(func() {
		file_attestation_format_proto_rawDescData = protoimpl.X.CompressGZIP(file_attestation_format_proto_rawDescData)
	})
	return file_attestation_format_proto_rawDescData
}

var file_attestation_format_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_attestation_format_proto_goTypes = []interface{}{
	(AttestationFormat)(0), // 0: proto.AttestationFormat
}
var file_attestation_format_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_attestation_format_proto_init() }
func file_attestation_format_proto_init() {
	if File_attestation_format_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_attestation_format_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_attestation_format_proto_goTypes,
		DependencyIndexes: file_attestation_format_proto_depIdxs,
		EnumInfos:         file_attestation_format_proto_enumTypes,
	}.Build()
	File_attestation_format_proto = out.File
	file_attestation_format_proto_rawDesc = nil
	file_attestation_format_proto_goTypes = nil
	file_attestation_format_proto_depIdxs = nil
}
