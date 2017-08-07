#include <string.h>

#define NRF_LOG_MODULE_NAME "CRYP"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

#include "mi_secure.h"
#include "mi_type.h"
#include "mi_crypto.h"
#include "ccm.h"

typedef struct {
	uint16_t low;
	uint16_t high;
} counter_t;

typedef struct { 
	uint8_t   iv[4];
	uint8_t   reserve[4];
	uint32_t  counter;
} session_nonce_t;

typedef struct {
	uint8_t mac[6];
	uint8_t pid[2];
	uint8_t cnt[4];
} beacon_nonce_t;

static struct {
	uint8_t initialized :1;
	uint8_t encrypting  :1;
	uint8_t decrypting  :1;
	uint8_t pending     :1;
	uint8_t processing  :1;
} m_flags;

static uint32_t  session_dev_cnt;
static uint32_t  session_app_cnt;
static uint8_t  dev_iv[4];
static uint8_t  app_iv[4];
static uint8_t  session_key_dev[16];
static uint8_t  session_key_app[16];

static int update_cnt(uint32_t* p_cnt, uint16_t cnt_low)
{
	uint16_t old_cnt_low = *p_cnt;
	
	if (((old_cnt_low ^ cnt_low) & 0x8000) != 0)
		*p_cnt += 0x10000UL;
	
	*(uint16_t*)p_cnt = cnt_low;

	return 0;
}

int mi_encrypt_init(session_key_t *pkey)
{
	if (pkey == NULL)
		return 1;

	memcpy(session_key_dev, pkey->dev_key, 16);
	memcpy(session_key_app, pkey->app_key, 16);
	memcpy(dev_iv, pkey->dev_iv, sizeof(dev_iv));
	memcpy(app_iv, pkey->app_iv, sizeof(dev_iv));
	session_app_cnt = 0;
	session_dev_cnt = 0;

	m_flags.initialized = 1;
	return 0;
}

int mi_encrypt_uninit()
{
	m_flags.initialized = 0;
	return 0;
}


int mi_session_encrypt(uint8_t *input, uint8_t len, uint8_t *output)
{
	uint32_t ret = 0;

	if (m_flags.initialized != 1)
		ret = 1;

	CRITICAL_REGION_ENTER();
	if (m_flags.processing == 1)
		ret = 2;
	else
		m_flags.processing = 1;
	CRITICAL_REGION_EXIT();

	if (ret)
		return ret;

	uint8_t tmp[len];
	memcpy(tmp, input, len);
	
	session_nonce_t nonce = {0};
	memcpy(nonce.iv, dev_iv, sizeof(dev_iv));
	uint16_t cnt_low = (uint16_t)session_dev_cnt;
	update_cnt(&session_dev_cnt, ++cnt_low);
	nonce.counter = session_dev_cnt;
	
	aes_ccm_encrypt_and_tag(session_key_dev, (void*)&nonce, sizeof(nonce), NULL, 0,
	                        tmp, len, 2+output, 2+output+len, 4);

	*(uint16_t*)output = session_dev_cnt;

	m_flags.processing = 0;
	return 0;
}

int mi_session_decrypt(uint8_t *input, uint8_t len, uint8_t *output)
{
	uint32_t ret = 0;

	if (m_flags.initialized != 1)
		ret = 1;

	CRITICAL_REGION_ENTER();
	if (m_flags.processing == 1)
		ret = 2;
	else
		m_flags.processing = 1;
	CRITICAL_REGION_EXIT();

	if (ret)
		return ret;
	
	session_nonce_t nonce = {0};
	memcpy(nonce.iv, app_iv, sizeof(app_iv));
	uint16_t cnt_low = input[1]<<8 | input[0];
	update_cnt(&session_app_cnt, cnt_low);
	nonce.counter = session_app_cnt;

	ret = aes_ccm_auth_decrypt(session_key_app, (void*)&nonce, sizeof(nonce), NULL, 0,
	                           2+input, len-6, output, 2+input+len-6, 4);

	m_flags.processing = 0;
	return ret;
}
