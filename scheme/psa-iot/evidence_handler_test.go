// Copyright 2021-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package psa_iot

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/veraison/ear"
	"github.com/veraison/services/proto"
)

func Test_GetTrustAnchorID_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/psa-token.cbor")
	require.NoError(t, err)

	token := proto.AttestationToken{
		TenantId: "1",
		Data:     tokenBytes,
	}

	expectedTaID := "PSA_IOT://1/BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=/AQcGBQQDAgEADw4NDAsKCQgXFhUUExIREB8eHRwbGhkY"

	handler := &EvidenceHandler{}

	taID, err := handler.GetTrustAnchorID(&token)
	require.NoError(t, err)
	assert.Equal(t, expectedTaID, taID)
}

func Test_ExtractVerifiedClaimsInteg_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/psaintegtoken.cbor")
	require.NoError(t, err)

	taEndValBytes, err := os.ReadFile("test/ta-integ-endorsements.json")
	require.NoError(t, err)

	handler := &EvidenceHandler{}

	token := proto.AttestationToken{
		TenantId: "0",
		Data:     tokenBytes,
	}

	_, err = handler.ExtractClaims(&token, string(taEndValBytes))

	require.NoError(t, err)

}

func Test_ExtractVerifiedClaims_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/psa-token.cbor")
	require.NoError(t, err)

	taEndValBytes, err := os.ReadFile("test/ta-endorsements.json")
	require.NoError(t, err)

	handler := &EvidenceHandler{}

	token := proto.AttestationToken{
		TenantId: "1",
		Data:     tokenBytes,
	}

	extracted, err := handler.ExtractClaims(&token, string(taEndValBytes))

	require.NoError(t, err)
	assert.Equal(t, "PSA_IOT_PROFILE_1", extracted.ClaimsSet["psa-profile"].(string))

	swComponents := extracted.ClaimsSet["psa-software-components"].([]interface{})
	assert.Len(t, swComponents, 4)
	assert.Equal(t, "BL", swComponents[0].(map[string]interface{})["measurement-type"].(string))
}

func Test_ValidateEvidenceIntegrity_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/psa-token.cbor")
	require.NoError(t, err)

	taEndValBytes, err := os.ReadFile("test/ta-endorsements.json")
	require.NoError(t, err)

	handler := &EvidenceHandler{}

	token := proto.AttestationToken{
		TenantId: "1",
		Data:     tokenBytes,
	}

	err = handler.ValidateEvidenceIntegrity(&token, string(taEndValBytes), nil)

	assert.NoError(t, err)
}

func Test_AppraiseEvidence_ok(t *testing.T) {
	extractedBytes, err := os.ReadFile("test/extracted.json")
	require.NoError(t, err)

	var ec proto.EvidenceContext
	err = json.Unmarshal(extractedBytes, &ec)
	require.NoError(t, err)

	endorsementsBytes, err := os.ReadFile("test/endorsements.json")
	require.NoError(t, err)

	handler := &EvidenceHandler{}

	result, err := handler.AppraiseEvidence(&ec, []string{string(endorsementsBytes)})
	require.NoError(t, err)

	attestation := result.Submods["PSA_IOT"]

	assert.Equal(t, ear.TrustTierAffirming, *attestation.Status)
}

func Test_AppraiseEvidenceMultEndorsement_ok(t *testing.T) {
	extractedBytes, err := os.ReadFile("test/extracted.json")
	require.NoError(t, err)

	var ec proto.EvidenceContext
	err = json.Unmarshal(extractedBytes, &ec)
	require.NoError(t, err)

	var endorsemementsArray []string
	endorsementsBytes, err := os.ReadFile("test/mult-endorsements.json")
	require.NoError(t, err)
	err = json.Unmarshal(endorsementsBytes, &endorsemementsArray)
	require.NoError(t, err)

	handler := &EvidenceHandler{}

	result, err := handler.AppraiseEvidence(&ec, endorsemementsArray)
	require.NoError(t, err)

	attestation := result.Submods["PSA_IOT"]

	assert.Equal(t, ear.TrustTierAffirming, *attestation.Status)
}
