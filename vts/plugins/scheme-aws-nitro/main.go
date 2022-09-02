// Copyright 2021-2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	//"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"

	"github.com/hashicorp/go-plugin"
	"github.com/veracruz-project/go-nitro-enclave-attestation-document"
	"github.com/veraison/services/proto"
	"github.com/veraison/services/scheme"
)

type Endorsements struct {
}

type Scheme struct{}

func (s Scheme) GetName() string {
	return proto.AttestationFormat_AWS_NITRO.String()
}

func (s Scheme) GetFormat() proto.AttestationFormat {
	return proto.AttestationFormat_AWS_NITRO
}

func (s Scheme) SynthKeysFromSwComponent(tenantID string, swComp *proto.Endorsement) ([]string, error) {

	var return_array []string // intentionally empty, because we have no SW components in our provisioning corim at this time
	return return_array, nil
}

func (s Scheme) SynthKeysFromTrustAnchor(tenantID string, ta *proto.Endorsement) ([]string, error) {	
	return []string{nitroTaLookupKey(tenantID)}, nil
}

func (s Scheme) GetSupportedMediaTypes() []string {
	return []string{
		"application/aws-nitro-document",
	}
}

func (s Scheme) GetTrustAnchorID(token *proto.AttestationToken) (string, error) {

	return nitroTaLookupKey(token.TenantId), nil
}

func (s Scheme) ExtractVerifiedClaims(token *proto.AttestationToken, trustAnchor string) (*scheme.ExtractedClaims, error) {

	ta_unmarshalled := make(map[string]interface{})

	err := json.Unmarshal([]byte(trustAnchor), &ta_unmarshalled)
	if err != nil {
		new_err := fmt.Errorf("ExtractVerifiedClaims call to json.Unmarshall failed:%v", err)
		return nil, new_err
	}
	contents, ok := ta_unmarshalled["attributes"].(map[string]interface{})
	if !ok {
		new_err:= fmt.Errorf("scheme-aws-nitro.Scheme.ExtractVerifiedClaims cast of %v to map[string]interface{} failed", ta_unmarshalled["attributes"])
		return nil, new_err
	}

	cert_pem, ok := contents["nitro.iak-pub"].(string)
	if !ok {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractVerifiedClaims cast of %v to string failed", contents["nitro.iak-pub"])
		return nil, new_err
	}

	// golang standard library pem.Decode function cannot handle PEM data without a header, so I have to add one to make it happy. 
	// Yes, this is stupid
	cert_pem = "-----BEGIN CERTIFICATE-----\n" + cert_pem + "\n-----END CERTIFICATE-----\n"
	cert_pem_bytes := []byte(cert_pem)
	cert_block, _ := pem.Decode(cert_pem_bytes)
	if cert_block == nil {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractVerifiedClaims call to pem.Decode failed, but I don't know why")
		return nil, new_err
	}

	cert_der := cert_block.Bytes
	cert, err := x509.ParseCertificate(cert_der)
	if err != nil {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractVerifiedClaims call to x509.ParseCertificate failed:%v", err)
		return nil, new_err
	}

	// token_data, err := base64.StdEncoding.DecodeString(string(token.Data))
	// if err != nil {
	// 	new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractVerifiedClaims call to base64.StdEncoding.DecodeString failed:%v", err)
	// 	return nil, new_err
	// }
	token_data := token.Data

	document, err := nitro_eclave_attestation_document.AuthenticateDocument(token_data, *cert)
	if err != nil {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractVerifiedClaims call to AuthenticateDocument failed:%v", err)
		return nil, new_err
	}

	var extracted scheme.ExtractedClaims

	claimsSet, err := claimsToMap(document)
	if err != nil {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractVerifiedClaims call to claimsToMap failed:%v", err)
		return nil, new_err
	}
	extracted.ClaimsSet = claimsSet

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

func claimsToMap(doc *nitro_eclave_attestation_document.AttestationDocument) (out map[string]interface{}, err error) {
	out = make(map[string]interface{})
	for index, this_pcr := range doc.PCRs {
		var key = fmt.Sprintf("PCR%v", index)
		out[key] = this_pcr
	}
	out["user_data"] = doc.User_Data
	out["nonce"] = doc.Nonce

	return out, nil
}

func populateAttestationResult(appraisalCtx *proto.AppraisalContext, endorsements []Endorsements) error {
	tv := proto.TrustVector{
		SoftwareUpToDateness: proto.AR_Status_UNKNOWN,
		ConfigIntegrity:      proto.AR_Status_UNKNOWN,
		RuntimeIntegrity:     proto.AR_Status_UNKNOWN,
		CertificationStatus:  proto.AR_Status_UNKNOWN,
	}

	// once the signature on the token is verified, we can claim the HW is
	// authentic
	tv.HardwareAuthenticity = proto.AR_Status_SUCCESS

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

func nitroTaLookupKey(tenantID string) string {

	u := url.URL{
		Scheme: proto.AttestationFormat_AWS_NITRO.String(),
		Host:   tenantID,
		Path:   "/",
	}

	return u.String()
}

func main() {
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

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins:         pluginMap,
	})
}
