package builtin

import (
	"github.com/veraison/services/plugin"

	scheme1 "github.com/veraison/services/scheme/amd-sev-snp"
	scheme2 "github.com/veraison/services/scheme/tpm-enacttrust"
	scheme3 "github.com/veraison/services/scheme/aws-nitro"
	scheme4 "github.com/veraison/services/scheme/tcg-dice"
	scheme5 "github.com/veraison/services/scheme/psa-iot"
	scheme6 "github.com/veraison/services/scheme/cca-ssd-platform"

)

var plugins = []plugin.IPluggable{
	&scheme1.EvidenceHandler{},
	&scheme1.EndorsementHandler{},
	&scheme2.EvidenceHandler{},
	&scheme2.EndorsementHandler{},
	&scheme3.EvidenceHandler{},
	&scheme3.EndorsementHandler{},
	&scheme4.EvidenceHandler{},
	&scheme5.EvidenceHandler{},
	&scheme5.EndorsementHandler{},
	&scheme6.EvidenceHandler{},
	&scheme6.EndorsementHandler{},
}

