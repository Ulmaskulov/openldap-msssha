#include <unistd.h>
#include <lber.h>
#include <lber_pvt.h>
#include "lutil.h"
#include "lutil_md5.h"
#include <ac/string.h>
#include "msssha.h"
#include <stdlib.h>

static LUTIL_PASSWD_CHK_FUNC chk_stub2;
static const struct berval scheme = BER_BVC("{MSSSHA}");

#define NS_MTA_MD5_PASSLEN	64
static int hash_stub2(const struct berval *scheme, const struct berval *passwd,
	struct berval *hash, const char **text)
{
    struct berval digest;
    char *hashedPass = mssshaFunction(passwd->bv_val, SALT_TO_USE);
    digest.bv_len = scheme->bv_len + strlen(hashedPass);
    digest.bv_val = (char *) ber_memalloc(digest.bv_len + 1);

    if (digest.bv_val == NULL) {
        return LUTIL_PASSWD_ERR;
    }

    AC_MEMCPY(digest.bv_val, scheme->bv_val, scheme->bv_len);
    AC_MEMCPY(&digest.bv_val[scheme->bv_len], hashedPass, strlen(hashedPass));

    digest.bv_val[digest.bv_len] = '\0';
    *hash = digest;
    free(hashedPass);

    return LUTIL_PASSWD_OK;
}

static int chk_stub2(const struct berval *scheme, const struct berval *passwd,
	const struct berval *cred, const char **text )
{
    char * hashedPassString = mssshaFunction((char *)cred->bv_val, SALT_TO_USE);
    if (hashedPassString == NULL)
    {
        return LUTIL_PASSWD_ERR;
    }

    int retVal = memcmp(hashedPassString, (char *)passwd->bv_val, passwd->bv_len);
    free(hashedPassString);
	return  retVal ? LUTIL_PASSWD_ERR : LUTIL_PASSWD_OK;
}

int init_module(int argc, char *argv[]) {
	return lutil_passwd_add( (struct berval *)&scheme, chk_stub2, hash_stub2 );
}
