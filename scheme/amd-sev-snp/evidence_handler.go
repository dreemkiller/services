// Copyright 2021-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package amd_sev_snp

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strconv"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"

	"github.com/veraison/ear"

	"github.com/veraison/services/handler"
	"github.com/veraison/services/proto"
)

type Attributes struct {
	Version string
	Policy string
	Family_id string
	Image_id string
	Signature_algo string
	Platform_version string
	Platform_info string
	Flags string
	Measurement string
	Host_data string
	Id_key_digest string
	Author_key_digest string
	Reported_tcb string
	Chip_id string
}
type Endorsements struct {
	Scheme 	string `json:"scheme"`
	Type   	string `json:"type"`
	SubType	string `json:"sub_type"`
	Attr	Attributes `json:"attributes"`
}
type EvidenceHandler struct {
}

func (o EvidenceHandler) GetName() string {
	return "amd-sev-snp-evidence-handler"
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
	attributes := refValue.GetAttributes().GetFields()
	hwModel := attributes["AMD-SEV-SNP.hw-model"].GetStringValue()
	//implId  := attributes["AMD-SEV-SNP.impl-id"]
	//platformConfigId := attributes["AMD-SEV-SNP.platform-config-id"]
	//platformConfigLabel := attributes["AMD-SEV-SNP.platform-config-label"]
	return [] string {amdSevSnpTaLookupKey(hwModel)}, nil
}

func (o EvidenceHandler) GetTrustAnchorID(token *proto.AttestationToken) (string, error) {
	return amdSevSnpTaLookupKey(token.TenantId), nil
}

func (o EvidenceHandler) SynthKeysFromTrustAnchor(tenantID string, ta *proto.Endorsement) ([]string, error) {
	return [] string{amdSevSnpTaLookupKey(tenantID)}, nil
}

func (o EvidenceHandler) ExtractClaims(
	token *proto.AttestationToken,
	trustAnchor string,
) (*handler.ExtractedClaims, error) {
	
	claims, _, err := extractClaimsOnly(token)
	if err != nil {
		return nil, fmt.Errorf("amd-sev-snp::EvidenceHandler::ExtractClaims call to extractClaimsOnly failed:%v", err)
	}

	return claims, nil
}

func (o EvidenceHandler) ValidateEvidenceIntegrity(
	token *proto.AttestationToken,
	trustAnchor string,
	endorsementsStrings []string,
) error {
	_, proto_report, err := extractClaimsOnly(token)
	if err != nil {
		return fmt.Errorf("amd-sev-snp::EvidenceHandler::ValidateEvidenceIntegrity call to extractClaimsOnly failed:%v", err)
	}

	ta_unmarshalled := make(map[string]interface{})

	err = json.Unmarshal([]byte(trustAnchor), &ta_unmarshalled)
	if err != nil {
		return fmt.Errorf("amd-sev-snp::EvidenceHandler::extractClaimsOnly call to json.Unmarshall failed:%v\n", err)
	}

	scheme := ta_unmarshalled["scheme"]
	if scheme != "AMD-SEV-SNP" {
		return fmt.Errorf("amd-sev-snp::EvidenceHandler::extractClaimsOnly invalid trustAnchor provided. Expected scheme 'AMD-SEV-SNP', received:%v", scheme)
	}
	contents, ok := ta_unmarshalled["attributes"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("amd-sev-snp::EvidenceHandler::extractClaimsOnly cast of %v to map[string]interface{} failed", ta_unmarshalled["attributes"])
	}

	cert_pem, ok := contents["amd-snp-milan.ark_cert"].(string)
	if !ok {
		new_err := fmt.Errorf("amd-sev-snp::EvidenceHandler::ValidateEvidenceIntegrity cast of %v to string failed", contents["amd-snp-milan.ark_cert"])
		return new_err
	}
	cert_block, _ := pem.Decode([]byte(cert_pem))
	if cert_block == nil {
		new_err := fmt.Errorf("amd-sev-snp::EvidenceHandler::ValidateEvidenceIntegrity call to pem.Decode failed, but I don't know why")
		return new_err
	}

	cert_der := cert_block.Bytes
	_, err = x509.ParseCertificate(cert_der)
	if err != nil {
		new_err := fmt.Errorf("amd-sev-snp::EvidenceHandler::ValidateEvidenceIntegrity call to x509.ParseCertificate failed:%v", err)
		return new_err
	}

	var attestation sevsnp.Attestation
	attestation.Report = proto_report
	err = verify.SnpAttestation(&attestation, verify.DefaultOptions())
	if err != nil {
		return fmt.Errorf("amd-sev-snp::EvidenceHandler::ValidateEvidenceIntegrity call to verify.SnpAttestation failed:%v", err)
	}
	return nil
}

func extractClaimsOnly(token *proto.AttestationToken) (*handler.ExtractedClaims, *sevsnp.Report, error) {

	proto_report, err := abi.ReportToProto(token.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("amd-sev-snp::EvidenceHandler::extractClaimsOnly call to abi.ReportToProto failed:%v", err)
	}

	claimsSet, err := claimsToMap(proto_report)
	if err != nil {
		return nil, nil, fmt.Errorf("amd-sev-snp::EvidenceHandler::extractClaimsOnly claimsToMap failed:%v", err)
	}

	var extracted handler.ExtractedClaims
	extracted.ClaimsSet = claimsSet

	return &extracted, proto_report, nil
}

func claimsToMap(report *sevsnp.Report) (out map[string]interface{}, err error) {
	out = make(map[string]interface{})
	out["report_data"] = report.ReportData
	out["measurement"] = report.Measurement
	out["host_data"] = report.HostData
	out["version"] = report.Version
	out["family_id"] = report.FamilyId
	out["platform_info"] = report.PlatformInfo
	return out, nil
}

func (o EvidenceHandler) AppraiseEvidence(
	ec *proto.EvidenceContext,
	endorsementsStrings []string,
) (*ear.AttestationResult, error) {
	var endorsements []Endorsements // nolint:prealloc

	result := handler.CreateAttestationResult(SchemeName)

	for i, e := range endorsementsStrings {
		var endorsement Endorsements

		if err := json.Unmarshal([]byte(e), &endorsement); err != nil {
			return nil, fmt.Errorf("amd-sev-snp::AppraiseEvidence could not decode endorsement at index %d: %w", i, err)
		}
		endorsements = append(endorsements, endorsement)
	}
	err := populateAttestationResult(result, ec.Evidence.AsMap(), endorsements)
	if err != nil {
		return nil, fmt.Errorf("amd-sev-snp::AppraiseEvidence populateAttestationResult failed:%v", err)
	}

	return result, nil
}

func amdSevSnpTaLookupKey(modelName string) string {

	u := url.URL{
		Scheme: SchemeName,
		Host:   modelName,
		Path:   "/",
	}

	return u.String()
}

func populateAttestationResult(
	result *ear.AttestationResult,
	evidence map[string]interface{},
	endorsements []Endorsements,
) error {

	appraisal := result.Submods[SchemeName]

	// Need to check the hardware version and firmware environment
	// not quite: also should check evidence["AMD-SEV-SNP.version"], evidence[""]
	if matchGenuineHardware(&evidence, &endorsements) {
		appraisal.TrustVector.Hardware = ear.GenuineHardwareClaim
	} else {
		appraisal.TrustVector.Hardware = ear.UnrecognizedHardwareClaim
	}

	// to check this, look at evidence["AMD-SEV-SNP.chip_id"]
	appraisal.TrustVector.InstanceIdentity = ear.TrustworthyInstanceClaim;
	// to check this, look at evidence["AMD-SEV-SNP.measurement"]
	//appraisal.TrustVector.RuntimeOpaque = ;
	// we don't have anything for this
	//appraisal.TrustVector.StorageOpaque = ;
	// we don't have anything for this
	//appraisal.TrustVector.Executables = ;
	//appraisal.UpdateStatusFromTrustVector();
	//appraisal.TrustVector.VeraisonAnnotatedEvidence = ;
	return nil
}

func matchGenuineHardware(evidence *map[string]interface{}, endorsements *[]Endorsements) bool {
	version := strconv.FormatFloat((*evidence)["version"].(float64), 'f', -1, 64)

	family_id := (*evidence)["family_id"].(string)
	platform_info := strconv.FormatFloat((*evidence)["platform_info"].(float64), 'f', -1, 64)
	match := false
	for _, endorsement := range *endorsements {
		if version != endorsement.Attr.Version {
			continue
		}
		if family_id != endorsement.Attr.Family_id {
			continue
		}
		if platform_info != endorsement.Attr.Platform_info {
			continue
		}
		match = true
		break

	}
	return match
}
