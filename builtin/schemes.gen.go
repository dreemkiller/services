package builtin

import (
	"github.com/veraison/services/plugin"

	scheme1 "github.com/veraison/services/scheme/cca-ssd-platform"
	scheme2 "github.com/veraison/services/scheme/psa-iot"
	scheme3 "github.com/veraison/services/scheme/tcg-dice"
	scheme4 "github.com/veraison/services/scheme/tpm-enacttrust"
	scheme5 "github.com/veraison/services/scheme/aws-nitro"

)

var plugins = []plugin.IPluggable{
	&scheme1.EndorsementHandler{},
	&scheme1.EvidenceHandler{},
	&scheme2.EndorsementHandler{},
	&scheme2.EvidenceHandler{},
	&scheme3.EvidenceHandler{},
	&scheme4.EndorsementHandler{},
	&scheme4.EvidenceHandler{},
	&scheme5.EndorsementHandler{},
	&scheme5.EvidenceHandler{},
}

