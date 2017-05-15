#ifndef __AES_CCM_H
#define __AES_CCM_H

#include <stdint.h>

uint8_t nrf_aes_ccm_encrypt_raw(uint8_t *key, uint8_t *iv, uint8_t *aStr, uint8_t *mic, uint8_t micLen, uint8_t *mStr, uint8_t mStrLen, uint8_t *result);
uint8_t nrf_aes_ccm_decrypt_raw(uint8_t *key, uint8_t *iv, uint8_t *aStr, uint8_t *mic, uint8_t micLen, uint8_t *mStr, uint8_t mStrLen, uint8_t *result);

#endif
