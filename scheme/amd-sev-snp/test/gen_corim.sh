#!/usr/bin/bash

cocli comid create --template AmdSevSnpComid.json
cocli corim create -m AmdSevSnpComid.cbor -t corimMini.json -o amd_sev_snp_corim.cbor
