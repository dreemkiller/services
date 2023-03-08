// Copyright 2021-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package aws_nitro

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"

	nitro_enclave_attestation_document "github.com/veracruz-project/go-nitro-enclave-attestation-document"

	"github.com/veraison/ear"

	"github.com/veraison/services/handler"
	"github.com/veraison/services/proto"
)

type Endorsements struct {
	Scheme 	string `json:"scheme"`
	Type   	string `json:"type"`
	SubType	string `json:"sub_type"`
	//Attr	SwAttr `json:"attributes"`
}
type EvidenceHandler struct {
}

func (o EvidenceHandler) GetName() string {
	return "aws-nitro-evidence-handler"
}

func (o EvidenceHandler) GetAttestationScheme() string {
	return SchemeName
}

func (o EvidenceHandler) GetSupportedMediaTypes() []string {
	return EvidenceMediaTypes
}

func (o EvidenceHandler) SynthKeysFromRefValue(
	tenantID string,
	refValue *proto.Endorsement,
) ([]string, error) {
	return nil, fmt.Errorf("Not yet implemented")	
}

func (o EvidenceHandler) GetTrustAnchorID(token *proto.AttestationToken) (string, error) {
	return nitroTaLookupKey(token.TenantId), nil
}

func (o EvidenceHandler) SynthKeysFromTrustAnchor(tenantID string, ta *proto.Endorsement) ([]string, error) {
	return []string{nitroTaLookupKey(tenantID)}, nil
}

func (o EvidenceHandler) ExtractClaims(
	token *proto.AttestationToken,
	trustAnchor string,
) (*handler.ExtractedClaims, error) {
	ta_unmarshalled := make(map[string]interface{})

	err := json.Unmarshal([]byte(trustAnchor), &ta_unmarshalled)
	if err != nil {
		new_err := fmt.Errorf("ExtractClaims call to json.Unmarshall failed:%v", err)
		return nil, new_err
	}
	contents, ok := ta_unmarshalled["attributes"].(map[string]interface{})
	if !ok {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractClaims cast of %v to map[string]interface{} failed", ta_unmarshalled["attributes"])
		return nil, new_err
	}

	cert_pem, ok := contents["aws-nitro.cert"].(string)
	if !ok {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractClaims cast of %v to string failed", contents["nitro.cert"])
		return nil, new_err
	}

	cert_pem_bytes := []byte(cert_pem)
	cert_block, _ := pem.Decode(cert_pem_bytes)
	if cert_block == nil {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractClaims call to pem.Decode failed, but I don't know why")
		return nil, new_err
	}

	cert_der := cert_block.Bytes
	cert, err := x509.ParseCertificate(cert_der)
	if err != nil {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractClaims call to x509.ParseCertificate failed:%v", err)
		return nil, new_err
	}

	token_data := token.Data

	document, err := nitro_enclave_attestation_document.AuthenticateDocument(token_data, *cert, false)
	if err != nil {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractClaims call to AuthenticateDocument failed:%v", err)
		return nil, new_err
	}

	var extracted handler.ExtractedClaims

	claimsSet, err := claimsToMap(document)
	if err != nil {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractClaims call to claimsToMap failed:%v", err)
		return nil, new_err
	}
	extracted.ClaimsSet = claimsSet

	return &extracted, nil
}


func (o EvidenceHandler) ValidateEvidenceIntegrity(
	token *proto.AttestationToken,
	trustAnchor string,
	endorsementsStrings []string,
) error {
	ta_unmarshalled := make(map[string]interface{})

	err := json.Unmarshal([]byte(trustAnchor), &ta_unmarshalled)
	if err != nil {
		new_err := fmt.Errorf("ValidateEvidenceIntegrity call to json.Unmarshall failed:%v", err)
		return new_err
	}
	contents, ok := ta_unmarshalled["attributes"].(map[string]interface{})
	if !ok {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ValidateEvidenceIntegrity cast of %v to map[string]interface{} failed", ta_unmarshalled["attributes"])
		return new_err
	}

	cert_pem, ok := contents["aws-nitro.cert"].(string)
	if !ok {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ValidateEvidenceIntegrity cast of %v to string failed", contents["nitro.cert"])
		return new_err
	}

	// golang standard library pem.Decode function cannot handle PEM data without a header, so I have to add one to make it happy.
	// Yes, this is stupid
	cert_pem = "-----BEGIN CERTIFICATE-----\n" + cert_pem + "\n-----END CERTIFICATE-----\n"
	cert_pem_bytes := []byte(cert_pem)
	cert_block, _ := pem.Decode(cert_pem_bytes)
	if cert_block == nil {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractVerifiedClaims call to pem.Decode failed, but I don't know why")
		return new_err
	}

	cert_der := cert_block.Bytes
	cert, err := x509.ParseCertificate(cert_der)
	if err != nil {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractVerifiedClaims call to x509.ParseCertificate failed:%v", err)
		return new_err
	}

	token_data := token.Data

	_, err = nitro_enclave_attestation_document.AuthenticateDocument(token_data, *cert, false)
	if err != nil {
		new_err := fmt.Errorf("scheme-aws-nitro.Scheme.ExtractVerifiedClaims call to AuthenticateDocument failed:%v", err)
		return new_err
	}
	return nil
}

func (o EvidenceHandler) AppraiseEvidence(
	ec *proto.EvidenceContext,
	endorsementsString []string,
) (*ear.AttestationResult, error) {
	var endorsements []Endorsements

	result := handler.CreateAttestationResult(SchemeName)

	for i, e := range endorsementsString {
		var endorsement Endorsements

		if err := json.Unmarshal([]byte(e), &endorsement); err != nil {
			return nil, fmt.Errorf("could not decode endorsement at index %d: %w", i, err)
		}

		endorsements = append(endorsements, endorsement)
	}

	err := populateAttestationResult(result, endorsements)

	return result, err
}

func nitroTaLookupKey(tenantID string) string {

	u := url.URL{
		Scheme: SchemeName,
		Host:   tenantID,
		Path:   "/",
	}

	return u.String()
}

func claimsToMap(doc *nitro_enclave_attestation_document.AttestationDocument) (out map[string]interface{}, err error) {
	out = make(map[string]interface{})
	for index, this_pcr := range doc.PCRs {
		var key = fmt.Sprintf("PCR%v", index)
		out[key] = this_pcr
	}
	out["user_data"] = doc.UserData
	out["nonce"] = doc.Nonce

	return out, nil
}

func populateAttestationResult(result *ear.AttestationResult, endorsements []Endorsements) error {
	// tv := proto.TrustVector{
	// 	InstanceIdentity: int32(proto.ARStatus_NO_CLAIM),
	// 	Configuration:    int32(proto.ARStatus_NO_CLAIM),
	// 	Executables:      int32(proto.ARStatus_NO_CLAIM),
	// 	FileSystem:       int32(proto.ARStatus_NO_CLAIM),
	// 	Hardware:         int32(proto.ARStatus_NO_CLAIM),
	// 	RuntimeOpaque:    int32(proto.ARStatus_NO_CLAIM),
	// 	StorageOpaque:    int32(proto.ARStatus_NO_CLAIM),
	// 	SourcedData:      int32(proto.ARStatus_NO_CLAIM),
	// }

	appraisal := result.Submods[SchemeName]

	appraisal.TrustVector.Hardware = ear.GenuineHardwareClaim
	
	//appraisal.TrustVector = &tv
	appraisal.TrustVector.InstanceIdentity = ear.TrustworthyInstanceClaim
	appraisal.TrustVector.RuntimeOpaque = ear.ApprovedRuntimeClaim
	appraisal.TrustVector.StorageOpaque = ear.HwKeysEncryptedSecretsClaim

	//appraisal.Status = proto.TrustTier_AFFIRMING
	appraisal.UpdateStatusFromTrustVector()

	//appraisal.ProcessedEvidence = appraisalCtx.Evidence.Evidence

	return nil
}