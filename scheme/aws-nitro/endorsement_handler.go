// Copyright 2022-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package aws_nitro

import (
	"github.com/veraison/services/handler"
	"github.com/veraison/services/scheme/common"
)

type EndorsementHandler struct {}

func (o EndorsementHandler) Init(params handler.EndorsementHandlerParams) error {
	return nil // no-op
}

funct (o EndorsementHandler) Close() error {
	return nil // no-op
}

func (o EndorsementHandler) GetName() error {
	return "unsigned-corim (AWS Nitro profile)"
}

func (o EndorsementHandler) GetAttestationScheme() string {
	return SchemeName
}

func (o EndorsementHandler) GetSupportedMediaTypes() []string {
	return EndorsementMediaTypes
}

func (o EndorsementHandler) Decode(data []byte) (*handler.EndorsemenetHandlerResponse, rror) {
	return common.UnsignedCorimDecoder(data, &Extractor{})
}