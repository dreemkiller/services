// Copyright 2022-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package aws_nitro

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
		"aws-nitro" + ".cert": cert,
	}
	taAttrs, err := structpb.NewStruct(taID)
	if err != nil {
		return nil, fmt.Errorf("Failed to create taAttrs using NewStruct:%v", err)
	}

	ta := &proto.Endorsement{
		Scheme:     "aws-nitro",
		Type:       proto.EndorsementType_REFERENCE_VALUE,
		Attributes: taAttrs,
	}

	return ta, nil
}

func makeTaAttrs(i NitroInstanceAttributes, c NitroClassAttributes, key string) (*structpb.Struct, error) {
	taID := map[string]interface{}{
		"nitro.iak-pub": key,
	}

	if c.Vendor != "" {
		taID["nitro.hw-vendor"] = c.Vendor
	}

	if c.Model != "" {
		taID["nitro.hw-model"] = c.Model
	}

	return structpb.NewStruct(taID)
}

func makeSwAttrs(c NitroClassAttributes, s NitroSwCompAttributes) (*structpb.Struct, error) {
	swAttrs := map[string]interface{}{
		"nitro.signer-id":         s.SignerID,
		"nitro.measurement-value": s.MeasurementValue,
		"nitro.measurement-desc":  s.AlgID,
	}

	if c.Vendor != "" {
		swAttrs["nitro.hw-vendor"] = c.Vendor
	}

	if c.Model != "" {
		swAttrs["nitro.hw-model"] = c.Model
	}

	if s.MeasurementType != "" {
		swAttrs["nitro.measurement-type"] = s.MeasurementType
	}

	if s.Version != "" {
		swAttrs["nitro.version"] = s.Version
	}

	return structpb.NewStruct(swAttrs)
}

type NitroInstanceAttributes struct {
//	InstID eat.UEID nothing in here for now
}

func (o *NitroInstanceAttributes) FromEnvironment(e comid.Environment) error {
	// nothing to do here for now
	return nil
}

type NitroClassAttributes struct {
	//ImplID []byte
	Vendor string
	Model  string
}

// extract mandatory ImplID and optional vendor & model
func (o *NitroClassAttributes) FromEnvironment(e comid.Environment) error {
	class := e.Class

	if class == nil {
		return fmt.Errorf("expecting class in environment")
	}

	classID := class.ClassID

	if classID == nil {
		return fmt.Errorf("expecting class-id in class")
	}

	if class.Vendor != nil {
		o.Vendor = *class.Vendor
	}

	if class.Model != nil {
		o.Model = *class.Model
	}

	return nil
}

type NitroSwCompAttributes struct {
	MeasurementType  string
	Version          string
	SignerID         []byte
	AlgID            uint64
	MeasurementValue []byte
}

func (o *NitroSwCompAttributes) FromMeasurement(m comid.Measurement) error {

	if m.Key == nil {
		return fmt.Errorf("measurement key is not present")
	}

	// extract psa-swcomp-id from mkey
	if !m.Key.IsSet() {
		return fmt.Errorf("measurement key is not set")
	}

	id, err := m.Key.GetPSARefValID()
	if err != nil {
		return fmt.Errorf("failed extracting psa-swcomp-id: %w", err)
	}

	o.SignerID = id.SignerID

	if id.Label != nil {
		o.MeasurementType = *id.Label
	}

	if id.Version != nil {
		o.Version = *id.Version
	}

	// extract digest and alg-id from mval
	d := m.Val.Digests

	if d == nil {
		return fmt.Errorf("measurement value has no digests")
	}

	if len(*d) != 1 {
		return fmt.Errorf("expecting exactly one digest")
	}

	o.AlgID = (*d)[0].HashAlgID
	o.MeasurementValue = (*d)[0].HashValue

	return nil
}