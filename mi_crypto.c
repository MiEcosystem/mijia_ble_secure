#include <string.h>

#define NRF_LOG_MODULE_NAME "CRYP"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

#include "mi_type.h"
#include "mi_crypto.h"
#include "ccm.h"

typedef struct { 
	uint8_t   iv[4];
	uint8_t   reserve[4];
	uint32_t  counter;
} session_nonce_t;

static struct {
	uint8_t initialized :1;
	uint8_t encrypting  :1;
	uint8_t decrypting  :1;
	uint8_t pending     :1;
	uint8_t processing  :1;
} m_flags;

static uint32_t  session_dev_cnt;
static uint32_t  session_app_cnt;
static session_ctx_t session_ctx;

static int update_cnt(uint32_t* p_cnt, uint16_t cnt_low)
{
	uint16_t old_cnt_low = *p_cnt;
	
	if (((old_cnt_low ^ cnt_low) & 0x8000) != 0)
		*p_cnt += 0x10000UL;
	
	*(uint16_t*)p_cnt = cnt_low;

	return 0;
}

int mi_crypto_init(session_ctx_t *p_ctx)
{
	if (p_ctx == NULL)
		return 1;

	session_ctx = *p_ctx;
	session_app_cnt = 0;
	session_dev_cnt = 0;

	m_flags.initialized = 1;
	return 0;
}

int mi_crypto_uninit(void)
{
	m_flags.initialized = 0;
	return 0;
}


int mi_session_encrypt(const uint8_t *input, uint8_t len, uint8_t *output)
{
	uint32_t ret = 0;

	if (m_flags.initialized != 1)
		return 1;

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
	memcpy(nonce.iv, session_ctx.dev_iv, sizeof(nonce.iv));
	uint16_t cnt_low = (uint16_t)session_dev_cnt;
	update_cnt(&session_dev_cnt, ++cnt_low);
	nonce.counter = session_dev_cnt;
	
	aes_ccm_encrypt_and_tag(session_ctx.dev_key, (void*)&nonce, sizeof(nonce), NULL, 0,
	                        tmp, len, 2+output, 2+output+len, 4);

	*(uint16_t*)output = session_dev_cnt;

	m_flags.processing = 0;
	return 0;
}

int mi_session_decrypt(const uint8_t *input, uint8_t len, uint8_t *output)
{
	uint32_t ret = 0;

	if (m_flags.initialized != 1)
		return 1;

	CRITICAL_REGION_ENTER();
	if (m_flags.processing == 1)
		ret = 2;
	else
		m_flags.processing = 1;
	CRITICAL_REGION_EXIT();

	if (ret)
		return ret;
	
	session_nonce_t nonce = {0};
	memcpy(nonce.iv, session_ctx.app_iv, sizeof(nonce.iv));
	uint16_t cnt_low = input[1]<<8 | input[0];
	update_cnt(&session_app_cnt, cnt_low);
	nonce.counter = session_app_cnt;

	ret = aes_ccm_auth_decrypt(session_ctx.app_key, (void*)&nonce, sizeof(nonce), NULL, 0,
	                           2+input, len-6, output, 2+input+len-6, 4);

	m_flags.processing = 0;
	return ret;
}
