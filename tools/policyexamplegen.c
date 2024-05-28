/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>

#include <pkcs11types.h>

#include <mechtable.h>

int main(void)
{
    size_t i;
    char *line = "";

    puts("# OpenCryptoki policy example");
    puts("# Move/copy to /etc/opencryptoki/policy.conf to use it with opencryptoki.");
    puts("# Then chown it to root:" PKCS_GROUP " and chmod it to 0640.");
    puts("# Also create a /etc/opencryptoki/strength.conf since this is a prerequisite");
    puts("# for policies.  You could just copy the strength-example.conf from this");
    puts("# folder, chown it to root:" PKCS_GROUP " and chmod it to 0640.");
    puts("");
    puts("version policy-0");
    puts("");
    puts("# Do not require any specific strength.");
    puts("# You probably do not want this!");
    puts("strength = 0");
    puts("");
    puts("# Allow all mechanisms by name.");
    puts("# A simpler option to configure this is to just remove the allowedmechs list.");
    puts("allowedmechs (");
    for (i = 0; i < MECHTABLE_NUM_ELEMS; ++i) {
        fputs(line, stdout);
        printf("       %s", mechtable_rows[i].string);
        line = ",\n";
    }
    putchar('\n');
    puts("       # No comma after last element!");
    puts(")");
    puts("");
    puts("# Allow all elliptic curves.");
    puts("# A simpler method to configure this is to just remove the allowedcurves list.");
    puts("allowedcurves (");
    puts("        BRAINPOOL_P160R1,");
    puts("        BRAINPOOL_P160T1,");
    puts("        BRAINPOOL_P192R1,");
    puts("        BRAINPOOL_P192T1,");
    puts("        BRAINPOOL_P224R1,");
    puts("        BRAINPOOL_P224T1,");
    puts("        BRAINPOOL_P256R1,");
    puts("        BRAINPOOL_P256T1,");
    puts("        BRAINPOOL_P320R1,");
    puts("        BRAINPOOL_P320T1,");
    puts("        BRAINPOOL_P384R1,");
    puts("        BRAINPOOL_P384T1,");
    puts("        BRAINPOOL_P512R1,");
    puts("        BRAINPOOL_P512T1,");
    puts("        PRIME192V1,");
    puts("        SECP224R1,");
    puts("        PRIME256V1,");
    puts("        SECP384R1,");
    puts("        SECP521R1,");
    puts("        SECP256K1,");
    puts("        CURVE25519,");
    puts("        CURVE448,");
    puts("        ED25519,");
    puts("        ED448");
    puts("        # No comma after last element!");
    puts(")");
    puts("");
    puts("# Allow all MGFs.");
    puts("# A simpler method to configure this is to just remove the allowedmgfs list.");
    puts("allowedmgfs (");
    puts("      CKG_MGF1_SHA1,");
    puts("      CKG_MGF1_SHA224,");
    puts("      CKG_MGF1_SHA256,");
    puts("      CKG_MGF1_SHA384,");
    puts("      CKG_MGF1_SHA512,");
    puts("      CKG_MGF1_SHA3_224,");
    puts("      CKG_MGF1_SHA3_256,");
    puts("      CKG_MGF1_SHA3_384,");
    puts("      CKG_MGF1_SHA3_512,");
    puts("      CKG_IBM_MGF1_SHA3_224,");
    puts("      CKG_IBM_MGF1_SHA3_256,");
    puts("      CKG_IBM_MGF1_SHA3_384,");
    puts("      CKG_IBM_MGF1_SHA3_512");
    puts("      # No comma after last element!");
    puts(")");
    puts("");
    puts("# Allow all KDFs.");
    puts("# A simpler method to configure this is to just remove the allowedkdfs list.");
    puts("allowedkdfs (");
    puts("      CKD_NULL,");
    puts("      CKD_SHA1_KDF,");
    puts("      CKD_SHA1_KDF_ASN1,");
    puts("      CKD_SHA1_KDF_CONCATENATE,");
    puts("      CKD_SHA224_KDF,");
    puts("      CKD_SHA256_KDF,");
    puts("      CKD_SHA384_KDF,");
    puts("      CKD_SHA512_KDF,");
    puts("      CKD_SHA3_224_KDF,");
    puts("      CKD_SHA3_256_KDF,");
    puts("      CKD_SHA3_384_KDF,");
    puts("      CKD_SHA3_512_KDF,");
    puts("      CKD_SHA1_KDF_SP800,");
    puts("      CKD_SHA224_KDF_SP800,");
    puts("      CKD_SHA256_KDF_SP800,");
    puts("      CKD_SHA384_KDF_SP800,");
    puts("      CKD_SHA512_KDF_SP800,");
    puts("      CKD_SHA3_224_KDF_SP800,");
    puts("      CKD_SHA3_256_KDF_SP800,");
    puts("      CKD_SHA3_384_KDF_SP800,");
    puts("      CKD_SHA3_512_KDF_SP800,");
    puts("      CKD_IBM_HYBRID_NULL,");
    puts("      CKD_IBM_HYBRID_SHA1_KDF,");
    puts("      CKD_IBM_HYBRID_SHA224_KDF,");
    puts("      CKD_IBM_HYBRID_SHA256_KDF,");
    puts("      CKD_IBM_HYBRID_SHA384_KDF,");
    puts("      CKD_IBM_HYBRID_SHA512_KDF");
    puts("      # No comma after last element!");
    puts(")");
    puts("");
    puts("# Allow all PRFs.");
    puts("# A simpler method to configure this is to just remove the allowedprfs list.");
    puts("allowedprfs (");
    puts("      CKP_PKCS5_PBKD2_HMAC_SHA256,");
    puts("      CKP_PKCS5_PBKD2_HMAC_SHA512");
    puts("      # No comma after last element!");
    puts(")");
    return 0;
}
