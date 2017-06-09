#include <string.h>
#include "mi_type.h"
#include "mi_crypto.h"
#include "aes_ccm.h"

typedef uint8_t (key_t)[16];
typedef uint8_t (iv_t) [4];

typedef struct {
	iv_t      iv;
	uint8_t   reserve[4];
	uint32_t  counter;
} session_nonce_t;

typedef struct {
	uint8_t   mac[6];
	uint8_t   pid[2];
	uint8_t   cnt[4];
} beacon_nonce_t;

static session_nonce_t session_nonce;
static uint32_t  session_dev_cnt;
static uint32_t  session_app_cnt;
static uint32_t  session_frame_cnt;
static key_t   session_key_dev;
static key_t   session_key_app;



int mi_beacon_encrypt()
{
	return 0;
}

int mi_beacon_decrypt()
{
	return 0;
}

int set_session_key_and_iv(key_t devkey, key_t appkey, iv_t iv)
{
	session_dev_cnt = 0;
	session_app_cnt = 0;
	memcpy(session_nonce.iv,    (uint8_t*)iv, 4);
	memcpy(session_key_dev, (uint8_t*)devkey, sizeof(devkey));
	memcpy(session_key_app, (uint8_t*)appkey, sizeof(appkey));

	return 0;
}

int mi_session_encrypt(uint8_t *input, uint8_t len, uint8_t *output)
{
	session_dev_cnt++;
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
