// Copyright 2022-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package amd_sev_snp

import(
	"errors"
	"fmt"

	"github.com/veraison/corim/comid"

	"github.com/veraison/services/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

type Extractor struct {
}

func (o Extractor) RefValExtractor(rv comid.ReferenceValue) ([]*proto.Endorsement, error) {
	return nil, fmt.Errorf("RefValExtractor: Not yet implemented")
}

func (o Extractor) TaExtractor(avk comid.AttestVerifKey) (*proto.Endorsement, error) {
	if len(avk.VerifKeys) != 1 {
		return nil, errors.New("expecting exactly 1 VerifKey")
	}
	cert := avk.VerifKeys[0].Key
	taID := map[string]interface{}{
		"amd-snp-milan" + ".ark_cert": cert,
	}
	taAttrs, err := structpb.NewStruct(taID)
	if err != nil {
		return nil, fmt.Errorf("Failed to create taAttrs using NewStruct:%v", err)
	}

	ta := &proto.Endorsement{
		Scheme:     SchemeName,
		Type:       proto.EndorsementType_REFERENCE_VALUE,
		Attributes: taAttrs,
	}

	return ta, nil
}

func makeTaAttrs(i AmdSevSnpInstanceAttributes, c AmdSevSnpClassAttributes, key string) (*structpb.Struct, error) {
	return nil, fmt.Errorf("makeTaAttrs: Not yet implemented")
}

func makeSwAttrs(c AmdSevSnpClassAttributes, s AmdSevSnpSwCompAttributes) (*structpb.Struct, error) {
	return nil, fmt.Errorf("makeSwAttrs: Not yet implemented")
}

type AmdSevSnpInstanceAttributes struct {
//	InstID eat.UEID nothing in here for now
}

func (o *AmdSevSnpInstanceAttributes) FromEnvironment(e comid.Environment) error {
	// nothing to do here for now
	return nil
}

type AmdSevSnpClassAttributes struct {
	//ImplID []byte
	Vendor string
	Model  string
}

// extract mandatory ImplID and optional vendor & model
func (o *AmdSevSnpClassAttributes) FromEnvironment(e comid.Environment) error {

	return fmt.Errorf("FromEnvironment: Not yet implemented")
}

type AmdSevSnpSwCompAttributes struct {
	MeasurementType  string
	Version          string
	SignerID         []byte
	AlgID            uint64
	MeasurementValue []byte
}

func (o *AmdSevSnpSwCompAttributes) FromMeasurement(m comid.Measurement) error {

	return fmt.Errorf("FromMeasurement: Not yet implemented")
}