#ifndef __MI_CRYPTO_H__
#define __MI_CRYPTO_H__
#include <stdint.h>

typedef struct {
	uint8_t dev_key[16];
	uint8_t app_key[16];
	uint8_t dev_iv[4];
	uint8_t app_iv[4];
	uint8_t reserve[24];
} session_key_t;

typedef enum {
	DEV_NONCE,
	APP_NONCE,
	BEACON_NONCE
} nonce_t;

int mi_encrypt_init(session_key_t *pkey);

/**@brief Function for encrypt the data.
 *
 * @details After Secure auth login, device and application will both generate the
 * same session key. This key will used to encrypt the data by AES128-CCM. The 
 * output is concatenating LSB of counter in nonce, cipher text and the MIC. So
 * the length of output buffer MUST be 6 bytes larger than input buffer.
 *
 * @param[in] input    plain text.
 * @param[in] len      plain text bytes.
 * @param[out] output  cipher text and 6-bytes extra info.
 */
int mi_session_encrypt(uint8_t *input, uint8_t len, uint8_t *output);

/**@brief Function for handling the Xiaomi Service's BLE events.
 *
 * @param[in] input    cipher text and 6-bytes extra info.
 * @param[in] len      num of byte.
 * @param[out] output  plain text.
 */
int mi_session_decrypt(uint8_t *input, uint8_t len, uint8_t *output);
#endif  /* __MI_CRYPTO_H__ */ 


