#ifndef __MI_CRYPTO_H__
#define __MI_CRYPTO_H__
#include <stdint.h>

typedef struct {
	uint8_t dev_key[16];
	uint8_t app_key[16];
	uint8_t      iv[4];
	uint8_t reserve[28];
} session_key_t;


#endif  /* __MI_CRYPTO_H__ */ 


