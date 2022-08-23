// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/hashicorp/go-plugin"
	"github.com/veraison/psatoken"
	"github.com/veraison/services/proto"
	"github.com/veraison/services/scheme"
	//"github.com/veraison/services/vts/plugins/common"
	//structpb "google.golang.org/protobuf/types/known/structpb"
)

type Endorsements struct {
	SwComponents []psatoken.SwComponent `json:"software-components"`
}

type Scheme struct{}

func (s Scheme) GetName() string {
	return proto.AttestationFormat_AWS_NITRO.String()
}

func (s Scheme) GetFormat() proto.AttestationFormat {
	log.Printf("scheme-aws-nitro.GetFormat called. Returning %v\n", proto.AttestationFormat_AWS_NITRO)
	return proto.AttestationFormat_AWS_NITRO
}

func (s Scheme) SynthKeysFromSwComponent(tenantID string, swComp *proto.Endorsement) ([]string, error) {
	//var (
		//implID string
//		fields map[string]*structpb.Value
		//err    error
	//)

	// fields, err = common.GetFieldsFromParts(swComp.GetAttributes())
	// if err != nil {
	// 	return nil, fmt.Errorf("unable to synthesize software component abs-path: %w", err)
	// }

	var return_array []string // intentionally empty, because we have no SW components in our provisioning corim at this time
	return return_array, nil
}

func (s Scheme) SynthKeysFromTrustAnchor(tenantID string, ta *proto.Endorsement) ([]string, error) {
	// var (
	// 	fields map[string]*structpb.Value
	// 	err    error
	// )

	// fields, err = common.GetFieldsFromParts(ta.GetAttributes())
	// if err != nil {
	// 	return nil, fmt.Errorf("unable to synthesize trust anchor abs-path: %w", err)
	// }

	

	return []string{nitroTaLookupKey(tenantID)}, nil
}

func (s Scheme) GetSupportedMediaTypes() []string {
	return []string{
		"application/aws-nitro-document",
	}
}

func (s Scheme) GetTrustAnchorID(token *proto.AttestationToken) (string, error) {
	var psaToken psatoken.Evidence

	err := psaToken.FromCOSE(token.Data)
	if err != nil {
		return "", err
	}

	return nitroTaLookupKey(token.TenantId), nil
}

func (s Scheme) ExtractVerifiedClaims(token *proto.AttestationToken, trustAnchor string) (*scheme.ExtractedClaims, error) {

	ta_unmarshalled := make(map[string]interface{})

	err := json.Unmarshal([]byte(trustAnchor), &ta_unmarshalled)
	if err != nil {
		return nil, err
	}

	contents := ta_unmarshalled["attributes"].(map[string]interface{})

	bytes, err := base64.StdEncoding.DecodeString(contents["psa.iak-pub"].(string))
	if err != nil {
		return nil, fmt.Errorf("Failed to base64 decode string: %s err:%e", contents["psa.iak-pub"].(string), err)
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), bytes)
	if x == nil {
		return nil, fmt.Errorf("Failed to Unmarhsal public key. No other information is available")
	}

	pk := ecdsa.PublicKey{
		elliptic.P256(),
		x,
		y,
	}

	var psaToken psatoken.Evidence

	if err = psaToken.FromCOSE(token.Data); err != nil {
		return nil, err
	}

	if err = psaToken.Verify(pk); err != nil {
		return nil, err
	}

	var extracted scheme.ExtractedClaims

	claimsSet, err := claimsToMap(psaToken.Claims)
	if err != nil {
		return nil, err
	}
	extracted.ClaimsSet = claimsSet

	// extracted.SoftwareID = psaSoftwareLookupKey(
	// 	token.TenantId,
	// 	MustImplIDString(psaToken.Claims),
	// )

	return &extracted, nil
}

func (s Scheme) AppraiseEvidence(
	ec *proto.EvidenceContext, endorsementsStrings []string,
) (*proto.AppraisalContext, error) {
	appraisalCtx := proto.AppraisalContext{
		Evidence: ec,
		Result:   &proto.AttestationResult{},
	}

	var endorsements []Endorsements

	for i, e := range endorsementsStrings {
		var endorsement Endorsements

		if err := json.Unmarshal([]byte(e), &endorsement); err != nil {
			return nil, fmt.Errorf("could not decode endorsement at index %d: %w", i, err)
		}

		endorsements = append(endorsements, endorsement)
	}

	err := populateAttestationResult(&appraisalCtx, endorsements)

	return &appraisalCtx, err
}

func claimsToMap(claims psatoken.IClaims) (map[string]interface{}, error) {
	data, err := claims.ToJSON()
	if err != nil {
		return nil, err
	}

	var out map[string]interface{}
	err = json.Unmarshal(data, &out)

	return out, err
}

func mapToClaims(in map[string]interface{}) (psatoken.IClaims, error) {
	data, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}

	return psatoken.DecodeJSONClaims(data)
}

func populateAttestationResult(appraisalCtx *proto.AppraisalContext, endorsements []Endorsements) error {
	tv := proto.TrustVector{
		SoftwareUpToDateness: proto.AR_Status_UNKNOWN,
		ConfigIntegrity:      proto.AR_Status_UNKNOWN,
		RuntimeIntegrity:     proto.AR_Status_UNKNOWN,
		CertificationStatus:  proto.AR_Status_UNKNOWN,
	}

	claims, err := mapToClaims(appraisalCtx.Evidence.Evidence.AsMap())
	if err != nil {
		return err
	}

	// once the signature on the token is verified, we can claim the HW is
	// authentic
	tv.HardwareAuthenticity = proto.AR_Status_SUCCESS

	match := matchSoftware(claims, endorsements)
	if match == nil {
		tv.SoftwareIntegrity = proto.AR_Status_FAILURE
	} else {
		tv.SoftwareIntegrity = proto.AR_Status_SUCCESS
	}

	appraisalCtx.Result.TrustVector = &tv

	if tv.SoftwareIntegrity != proto.AR_Status_FAILURE &&
		tv.HardwareAuthenticity != proto.AR_Status_FAILURE {
		appraisalCtx.Result.Status = proto.AR_Status_SUCCESS
	} else {
		appraisalCtx.Result.Status = proto.AR_Status_FAILURE
	}

	appraisalCtx.Result.ProcessedEvidence = appraisalCtx.Evidence.Evidence

	return nil
}

func matchSoftware(evidence psatoken.IClaims, endorsements []Endorsements) *Endorsements {
	evidenceComponents := make(map[string]psatoken.SwComponent)

	swComps, err := evidence.GetSoftwareComponents()
	if err != nil {
		return nil
	}

	for _, c := range swComps {
		key := base64.StdEncoding.EncodeToString(*c.MeasurementValue)
		evidenceComponents[key] = c
	}

	for _, endorsement := range endorsements {
		matched := true
		for _, comp := range endorsement.SwComponents {
			key := base64.StdEncoding.EncodeToString(*comp.MeasurementValue)
			evComp, ok := evidenceComponents[key]
			if !ok {
				matched = false
				break
			}

			typeMatched := *comp.MeasurementType == "" || *comp.MeasurementType == *evComp.MeasurementType
			sigMatched := comp.SignerID == nil || bytes.Equal(*comp.SignerID, *evComp.SignerID)
			versionMatched := *comp.Version == "" || *comp.Version == *evComp.Version

			if !(typeMatched && sigMatched && versionMatched) {
				matched = false
				break
			}
		}

		if matched {
			return &endorsement
		}
	}

	return nil
}

// func psaSoftwareLookupKey(tenantID, implID string) string {
// 	absPath := []string{implID}

// 	u := url.URL{
// 		Scheme: proto.AttestationFormat_AWS_NITRO.String(),
// 		Host:   tenantID,
// 		Path:   strings.Join(absPath, "/"),
// 	}

// 	return u.String()
// }

func nitroTaLookupKey(tenantID string) string {

	u := url.URL{
		Scheme: proto.AttestationFormat_AWS_NITRO.String(),
		Host:   tenantID,
		Path:   "/",
	}

	return u.String()
}

func MustImplIDString(c psatoken.IClaims) string {
	v, err := c.GetImplID()
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(v)
}

func MustInstIDString(c psatoken.IClaims) string {
	v, err := c.GetInstID()
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(v)
}

func main() {
	file, err := os.OpenFile("scheme_nitro.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	log.SetOutput(file)
	log.Println("scheme-aws-nitro main started")
	var handshakeConfig = plugin.HandshakeConfig{
		ProtocolVersion:  1,
		MagicCookieKey:   "VERAISON_PLUGIN",
		MagicCookieValue: "VERAISON",
	}

	var pluginMap = map[string]plugin.Plugin{
		"scheme": &scheme.Plugin{
			Impl: &Scheme{},
		},
	}

	log.Println("scheme-aws-nitro main calling plugin.Serve")
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins:         pluginMap,
	})
}
