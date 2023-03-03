// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package aws_nitro

const (
	SchemeName              = "AWS_NITRO"
	CCAEndorsementMediaType = "application/corim-unsigned+cbor; profile=http://aws.com/nitro"
)

var EndorsementMediaTypes = []string{
	"application/corim-unsigned+cbor; profile=http://aws.com/nitro",
}

var EvidenceMediaTypes = []string{
	"application/aws-nitro-document",
}
