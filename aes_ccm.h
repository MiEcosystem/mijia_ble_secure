#ifndef __AES_CCM_H
#define __AES_CCM_H

#include <stdint.h>

uint8_t aes_ccm_encrypt(
	uint8_t *key,  uint8_t *nonce,
	uint8_t *aStr, uint8_t aStr_len,
	uint8_t *mic,  uint8_t micLen,
	uint8_t *mStr, uint8_t mStrLen, uint8_t *result);

uint8_t aes_ccm_decrypt(
	uint8_t *key,  uint8_t *nonce,
	uint8_t *aStr, uint8_t aStr_len,
	uint8_t *mic,  uint8_t micLen,
	uint8_t *mStr, uint8_t mStrLen, uint8_t *result);

uint32_t soft_crc32(const void *pdata, uint32_t data_size, uint32_t crc);

#endif
