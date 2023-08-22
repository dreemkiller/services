// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package amd_sev_snp

const (
	SchemeName              = "AMD-SEV-SNP"
	SEVSNPEndorsementMediaType = "application/corim-unsigned+cbor; profile=https://amd.com/sev-snp"
	SEVSNPEvidenceMediaType = "application/amd-sev-snp-report"
)

var EndorsementMediaTypes = []string{
	SEVSNPEndorsementMediaType,
}

var EvidenceMediaTypes = []string{
	SEVSNPEvidenceMediaType,
}
