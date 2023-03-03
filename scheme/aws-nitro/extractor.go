// Copyright 2022-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package aws_nitro

import(
	"google.golang.org/protobuf/types/known/structpb"
)

type Extractor struct {
}

func (o Extractor) RefValExtractor(rv comid.ReferenceValue) ([]*proto.Endorsement, error) {
	var nitroClassAttrs NitroClassAttributes

	if err := nitroClassAttrs.FromEnvironment(rv.Environment); err != nil {
		return nil, fmt.Errorf("could not extract Nitro class attributes: %w", err)
	}

	swComponents := make([]*proto.Endorsement, 0, len(rv.Measurements))

	for i, m := range rv.Measurements {
		var nitroSwCompAttrs NitroSwCompAttributes

		if err := nitroSwCompAttrs.FromMeasurement(m); err != nil {
			return nil, fmt.Errorf("extracting measurement at index %d: %w", i, err)
		}

		swAttrs, err := makeSwAttrs(nitroClassAttrs, nitroSwCompAttrs)
		if err != nil {
			return nil, fmt.Errorf("failed to create software component attributes: %w", err)
		}

		swComponent := proto.Endorsement{
			Scheme:     proto.AttestationFormat_AWS_NITRO,
			Type:       proto.EndorsementType_REFERENCE_VALUE,
			Attributes: swAttrs,
		}

		swComponents = append(swComponents, &swComponent)
	}

	if len(swComponents) == 0 {
		return nil, fmt.Errorf("no software components found")
	}

	return swComponents, nil
}

func (o Extractor) TaExtractor(avk comid.AttestVerifKey) (*proto.Endorsement, error) {
	var nitroInstanceAttrs NitroInstanceAttributes

	if err := nitroInstanceAttrs.FromEnvironment(avk.Environment); err != nil {
		return nil, fmt.Errorf("could not extract Nitro instance-id: %w", err)
	}

	// extract implementation ID
	var nitroClassAttrs NitroClassAttributes

	if err := nitroClassAttrs.FromEnvironment(avk.Environment); err != nil {
		return nil, fmt.Errorf("could not extract Nitro class attributes: %w", err)
	}

	// extract IAK pub
	if len(avk.VerifKeys) != 1 {
		return nil, errors.New("expecting exactly one IAK public key")
	}

	iakPub := avk.VerifKeys[0].Key

	// TODO(tho) check that format of IAK pub is as expected

	taAttrs, err := makeTaAttrs(nitroInstanceAttrs, nitroClassAttrs, iakPub)
	if err != nil {
		return nil, fmt.Errorf("failed to create trust anchor attributes: %w", err)
	}

	ta := &proto.Endorsement{
		Scheme:     proto.AttestationFormat_AWS_NITRO,
		Type:       proto.EndorsementType_VERIFICATION_KEY,
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