// Copyright 2021-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tpm_enacttrust

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	tpm2 "github.com/google/go-tpm/tpm2"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/veraison/ear"

	"github.com/veraison/services/handler"
	"github.com/veraison/services/proto"
	"github.com/veraison/services/scheme/common"
)

type EvidenceHandler struct{}

func (s EvidenceHandler) GetName() string {
	return "tpm-enacttrust-evidence-handler"
}

func (s EvidenceHandler) GetAttestationScheme() string {
	return SchemeName
}

func (s EvidenceHandler) GetSupportedMediaTypes() []string {
	return EvidenceMediaTypes
}

func (s EvidenceHandler) SynthKeysFromRefValue(
	tenantID string,
	swComp *proto.Endorsement,
) ([]string, error) {
	return synthKeysFromParts("software component", tenantID, swComp.GetAttributes())
}

func (s EvidenceHandler) SynthKeysFromTrustAnchor(tenantID string, ta *proto.Endorsement) ([]string, error) {
	return synthKeysFromParts("trust anchor", tenantID, ta.GetAttributes())
}

func (s EvidenceHandler) GetTrustAnchorID(token *proto.AttestationToken) (string, error) {
	supported := false
	for _, mt := range EvidenceMediaTypes {
		if token.MediaType == mt {
			supported = true
			break
		}
	}

	if !supported {
		return "", fmt.Errorf("wrong media type: expect %q, but found %q",
			strings.Join(EvidenceMediaTypes, ", "),
			token.MediaType,
		)
	}

	var decoded Token

	if err := decoded.Decode(token.Data); err != nil {
		return "", err
	}

	return tpmEnactTrustLookupKey(token.TenantId, decoded.NodeId.String()), nil
}

func (s EvidenceHandler) ExtractClaims(
	token *proto.AttestationToken,
	trustAnchor string,
) (*handler.ExtractedClaims, error) {
	supported := false
	for _, mt := range EvidenceMediaTypes {
		if token.MediaType == mt {
			supported = true
			break
		}
	}

	if !supported {
		return nil, fmt.Errorf("wrong media type: expect %q, but found %q",
			strings.Join(EvidenceMediaTypes, ", "),
			token.MediaType,
		)
	}

	var decoded Token

	if err := decoded.Decode(token.Data); err != nil {
		return nil, fmt.Errorf("could not decode token: %w", err)
	}

	if decoded.AttestationData.Type != tpm2.TagAttestQuote {
		return nil, fmt.Errorf("wrong TPMS_ATTEST type: want %d, got %d",
			tpm2.TagAttestQuote, decoded.AttestationData.Type)
	}

	var pcrs []int64 // nolint:prealloc
	for _, pcr := range decoded.AttestationData.AttestedQuoteInfo.PCRSelection.PCRs {
		pcrs = append(pcrs, int64(pcr))
	}

	evidence := handler.NewExtractedClaims()
	evidence.ClaimsSet["pcr-selection"] = pcrs
	evidence.ClaimsSet["hash-algorithm"] = int64(decoded.AttestationData.AttestedQuoteInfo.PCRSelection.Hash)
	evidence.ClaimsSet["pcr-digest"] = []byte(decoded.AttestationData.AttestedQuoteInfo.PCRDigest)
	evidence.ReferenceID = tpmEnactTrustLookupKey(token.TenantId, decoded.NodeId.String())

	return evidence, nil
}

func (s EvidenceHandler) ValidateEvidenceIntegrity(
	token *proto.AttestationToken,
	trustAnchor string,
	endorsements []string,
) error {
	var decoded Token

	if err := decoded.Decode(token.Data); err != nil {
		return fmt.Errorf("could not decode token: %w", err)
	}

	pubKey, err := parseKey(trustAnchor)
	if err != nil {
		return fmt.Errorf("could not parse trust anchor: %w", err)
	}

	if err = decoded.VerifySignature(pubKey); err != nil {
		return fmt.Errorf("could not verify token signature: %w", err)
	}

	return nil
}

func (s EvidenceHandler) AppraiseEvidence(
	ec *proto.EvidenceContext,
	endorsementStrings []string,
) (*ear.AttestationResult, error) {
	result := handler.CreateAttestationResult(SchemeName)

	digestValue, ok := ec.Evidence.AsMap()["pcr-digest"]
	if !ok {
		return result, fmt.Errorf("evidence does not contain %q entry", "pcr-digest")
	}

	evidenceDigest, ok := digestValue.(string)
	if !ok {
		err := fmt.Errorf(
			"wrong type value %q entry; expected string but found %T",
			"pcr-digest",
			digestValue,
		)
		return result, err
	}

	var endorsements Endorsements
	if err := endorsements.Populate(endorsementStrings); err != nil {
		return result, err
	}

	appraisal := result.Submods[SchemeName]

	if endorsements.Digest == evidenceDigest {
		appraisal.TrustVector.Executables = ear.ApprovedRuntimeClaim
		*appraisal.Status = ear.TrustTierAffirming
	}

	return result, nil
}

func synthKeysFromParts(scope, tenantID string, parts *structpb.Struct) ([]string, error) {
	var (
		nodeID string
		fields map[string]*structpb.Value
		err    error
	)

	fields, err = common.GetFieldsFromParts(parts)
	if err != nil {
		return nil, fmt.Errorf("unable to synthesize %s abs-path: %w", scope, err)
	}

	nodeID, err = common.GetMandatoryPathSegment("enacttrust-tpm.node-id", fields)
	if err != nil {
		return nil, fmt.Errorf("unable to synthesize %s abs-path: %w", scope, err)
	}

	return []string{tpmEnactTrustLookupKey(tenantID, nodeID)}, nil
}

func parseKey(keyString string) (*ecdsa.PublicKey, error) {
	buf, err := base64.StdEncoding.DecodeString(keyString)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return nil, fmt.Errorf("could not parse public key: %v", err)
	}

	ret, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("could not extract EC public key; got [%T]: %v", key, err)
	}

	return ret, nil
}

func tpmEnactTrustLookupKey(tenantID, nodeID string) string {
	absPath := []string{nodeID}

	u := url.URL{
		Scheme: SchemeName,
		Host:   tenantID,
		Path:   strings.Join(absPath, "/"),
	}

	return u.String()
}
