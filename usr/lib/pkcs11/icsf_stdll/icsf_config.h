
#ifndef ICSF_CONFIG_H
#define ICSF_CONFIG_H

#include <limits.h>
#include "pkcs11types.h"
#include "icsf.h"

#define ICSF_CFG_MECH_SIMPLE 0
#define ICSF_CFG_MECH_SASL   1

/* ICSF specific slot data */
struct icsf_config {
	char name[ICSF_TOKEN_NAME_LEN + 1];
	char manuf[ICSF_MANUFACTURER_LEN + 1];
	char model[ICSF_MODEL_LEN + 1];
	char serial[ICSF_SERIAL_LEN + 1];
	char uri[PATH_MAX + 1];
	char dn[NAME_MAX + 1];
	char ca_file[PATH_MAX + 1];
	char cert_file[PATH_MAX + 1];
	char key_file[PATH_MAX + 1];
	int mech;
};

CK_RV
parse_config_file(const char *conf_name, CK_SLOT_ID slot_id,
		  struct icsf_config *data);

#endif
