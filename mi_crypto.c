#include <string.h>
#include "mi_type.h"
#include "mi_crypto.h"
#include "aes_ccm.h"
#include "ccm.h"

#define N   230
typedef struct {
	uint8_t   iv[4];
	uint8_t   reserve[4];
	uint32_t  counter;
} session_nonce_t;

typedef struct {
	uint8_t   mac[6];
	uint8_t   pid[2];
	uint8_t   cnt[4];
} beacon_nonce_t;


static session_nonce_t session_nonce;
static uint8_t  session_dev_cnt;
static uint8_t  session_app_cnt;
static uint8_t   session_key_dev[16];
static uint8_t   session_key_app[16];


int set_session_key_and_iv(session_key_t *pkey)
{
	if (pkey == NULL)
		return 1;

	memcpy(session_key_dev, pkey->dev_key, 16);
	memcpy(session_key_app, pkey->app_key, 16);

	memcpy(session_nonce.iv, pkey->iv, sizeof(session_nonce.iv));

	return 0;
}

int mi_session_encrypt(uint8_t *input, uint8_t len, uint8_t *output)
{
	session_dev_cnt++;
	if (session_dev_cnt > N)
		return 1;

	session_nonce.counter = session_dev_cnt;
	aes_ccm_encrypt((void*)session_key_dev, (void*)&session_nonce, NULL, 0,
	                output+len, 4, input, len, output);

	return 0;
}

int mi_session_decrypt(uint8_t *input, uint8_t len, uint8_t *output)
{
	session_app_cnt++;
	
	session_nonce.counter = session_app_cnt;
	aes_ccm_decrypt((void*)session_key_app, (void*)&session_nonce, NULL, 0,
	                input+len, 4, input, len, output);
	return 0;
}

#if 0


#endif
