#include <stdint.h>
#include <string.h>
#include "nrf_soc.h"

#define NRF_LOG_MODULE_NAME "AES"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

#include "aes_ccm.h"

#define AES_BLOCK_SIZE     16
#define MAX_ADATA_SIZE     16
#define MAX_DATA_SIZE      256
#define NONCE_LEN          12

typedef union {
	struct {
		uint8_t L : 3;
		uint8_t M : 3;
		uint8_t aData :1;
		uint8_t reserved :1;            
	} bf;
	uint8_t val;
} ccm_flags_t;

typedef struct {
    union {
        uint8_t A[AES_BLOCK_SIZE];
        uint8_t B[AES_BLOCK_SIZE];
    } bf;
    
    uint8_t tmpResult[AES_BLOCK_SIZE];
    uint8_t newAstr[AES_BLOCK_SIZE*2];
} aes_enc_t;

enum AES_OPT {
    AES_ENCRYPTION = 0,
    AES_DECRYPTION,
};

enum {
    AES_SUCC = 0,
    AES_NO_BUF,               
    AES_FAIL,
};

static void nrf_aes_ecb_encrypt(uint8_t* pKey, uint8_t* input, uint8_t* output)
{
	nrf_ecb_hal_data_t ecb_data;
	memcpy(ecb_data.key, pKey, 16);
	memcpy(ecb_data.cleartext, input, 16);
	sd_ecb_block_encrypt(&ecb_data);
	memcpy(output, ecb_data.ciphertext, 16);
}

#if 1
/*
 * Polynomial used to generate the table:
 * CRC-32-IEEE 802.3, the polynomial is :
 * x^32+x^26+x^23+x^22+x^16+x^12+x^11+x^10+x^8+x^7+x^5+x^4+x^2+x+1
 */
static uint32_t crc32_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3,	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5,	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,	0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,	0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t soft_crc32(const void *buf, size_t size, uint32_t crc)
{
	const uint8_t *p;

	p = buf;
	crc = crc ^ ~0U;

	while (size--)
		crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

	return crc ^ ~0U;
}

#endif

/*********************************************************************
 * @fn      aes_ccmBaseTran
 *
 * @brief   calc the aes ccm value 
 *
 * @param[in]     micLen - mic lenth (should be 4)
 *
 * @param[in]     nonce - iv[4] || reserved[4] = {0} || direction || pkgcounter[4] (should be 13 bytes)
 *
 * @param[in]     mStr - plaint text 
 *
 * @param[in]     mStrLen - plaint text length
 * 
 * @param[in]     aStr -  a string  (should be AAD the data channel PDU header’s first octet with NESN, SN and MD bits masked to 0)
 *
 * @param[in]     aStrLen - a atring lenth (should be 1)
 *
 * @param[out]    result - result (result)
 *
 * @return        status
 */
static uint8_t aes_ccmBaseTran(uint8_t micLen, uint8_t *key, uint8_t *nonce,
	uint8_t *mStr, uint16_t mStrLen, uint8_t *aStr, uint8_t aStrLen, uint8_t *mic, uint8_t opt)
{
    ccm_flags_t flags = {0};
    aes_enc_t  encTmp = {0};
    uint16_t  counter = 1;
    uint16_t i;
    uint8_t msgLen;
    uint8_t j;

    flags.bf.L = 14 - NONCE_LEN;
    encTmp.bf.A[0] = flags.val;

    /* set the nonce */
    memcpy(encTmp.bf.A+1, nonce, NONCE_LEN);

    nrf_aes_ecb_encrypt(key, encTmp.bf.A, encTmp.tmpResult);

    for ( i=0; i<micLen; i++ ) {
        mic[i] ^= encTmp.tmpResult[i];
    }
    
    encTmp.bf.A[14] = counter>>8;
    encTmp.bf.A[15] = counter & 0xff;
    
    msgLen = mStrLen;
    if (msgLen & 0x0f) {
        msgLen &= ~0x0F;
        msgLen += 0x10;
    }

    for ( i=0; i<msgLen; i+=AES_BLOCK_SIZE ) {
        /* use aes to the E(key, Ai) */
        nrf_aes_ecb_encrypt(key, encTmp.bf.A, encTmp.tmpResult);

        for ( j=0; (j<AES_BLOCK_SIZE) && (i+j < mStrLen); j++) {
            mStr[i+j] ^= encTmp.tmpResult[j];
        }

        /* update Ai */
        counter++;
        encTmp.bf.A[14] = counter>>8;
        encTmp.bf.A[15] = counter & 0xff;
    }
    
    return 0;
}

static uint8_t aes_ccmEncTran(uint8_t micLen, uint8_t *key, uint8_t *nonce,
	uint8_t *mStr, uint16_t mStrLen, uint8_t *aStr, uint8_t aStrLen, uint8_t *mic)
{
	return aes_ccmBaseTran(micLen, key, nonce, mStr, mStrLen, aStr, aStrLen, mic, AES_ENCRYPTION);
}

static uint8_t aes_ccmDecTran(uint8_t micLen, uint8_t *key, uint8_t *nonce,
	uint8_t *mStr, uint16_t mStrLen, uint8_t *aStr, uint8_t aStrLen, uint8_t *mic)
{
    return aes_ccmBaseTran(micLen, key, nonce, mStr, mStrLen, aStr, aStrLen, mic, AES_DECRYPTION);
}




/*********************************************************************
 * @fn      aes_ccmAuthTran
 *
 * @brief   calc the aes ccm mic value 
 *
 * @param[in]     micLen - mic lenth (should be 4)
 *
 * @param[in]     nonce - initial vector || reserved || packet counter
 *
 * @param[in]     mStr - plaint text 
 *
 * @param[in]     mStrLen - plaint text length
 *
 * @param[in]     aStr -  a string  (should be AAD the data channel PDU header’s first octet with NESN, SN and MD bits masked to 0)
 *
 * @param[in]     aStrLen - a atring lenth (must less than 30)
 *
 * @param[out]    result - Message integrity check (MIC)
 *
 * @return       status
 */
static uint8_t aes_ccmAuthTran(uint8_t micLen, uint8_t *key, uint8_t *nonce,
	uint8_t *mStr, uint16_t mStrLen, uint8_t *aStr, uint16_t aStrLen, uint8_t *result)
{
    aes_enc_t enc_tmp = {0};
	ccm_flags_t flags = {0};
    uint8_t mStrIndex = 0;
	uint16_t msgLen;
    uint16_t i,j;

    if ( aStrLen > 30 ) {
        return 1;
    }
	else if (aStr != NULL && aStrLen > 0) {
		enc_tmp.newAstr[0] = aStrLen>>8;
		enc_tmp.newAstr[1] = aStrLen & 0xff;
		memcpy(enc_tmp.newAstr + 2, aStr, aStrLen);
		aStrLen += 2;
	}
	else {
		aStrLen = 0;
	}

    /* Encode FLAGS */
    flags.bf.L = 14 - NONCE_LEN;  /* LEN - 1 (15-nonceLen-1)*/
    flags.bf.M = (micLen - 2)>>1;
    flags.bf.aData = (aStrLen > 0) ? 1 : 0;

    /* B0 = FLAGS || NONCE || MSTR_LEN */
    enc_tmp.bf.B[0] = flags.val;
    memcpy(enc_tmp.bf.B + 1, nonce, NONCE_LEN);
    enc_tmp.bf.B[14] = mStrLen>>8;
    enc_tmp.bf.B[15] = mStrLen & 0xff;

    /* X0 is zero */
    memset(enc_tmp.tmpResult, 0, AES_BLOCK_SIZE);

    /* adjust msgLen according to aStrLen and mStrLen, should be 16x */
    msgLen = aStrLen;
    if (aStrLen & 0x0f) {
        msgLen &= ~0x0F;
        msgLen += 0x10;
    }

    msgLen += mStrLen;
    if (mStrLen & 0x0f) {
        msgLen &= ~0x0F;
        msgLen += 0x10;
    }

    
    /* now the msgLen should be the length of AuthData, which is generated by AddAuthData (astring, padded by 0) || PlaintexeData (mString, padded by 0)*/
    for (i = 0; i < msgLen + 16; i += AES_BLOCK_SIZE ) {
        for (j = 0; j < AES_BLOCK_SIZE; j++) {
            /* get Xi XOR Bi */
            enc_tmp.tmpResult[j] ^= enc_tmp.bf.B[j];
        }

        /* use aes to get E(key, Xi XOR Bi) */
        nrf_aes_ecb_encrypt(key, enc_tmp.tmpResult, enc_tmp.tmpResult);

        /* update B */
        if ( aStrLen >= AES_BLOCK_SIZE ) {
            memcpy(enc_tmp.bf.B, enc_tmp.newAstr + i, AES_BLOCK_SIZE);
            aStrLen -= AES_BLOCK_SIZE;
        } else if ( aStrLen > 0 && aStrLen < AES_BLOCK_SIZE) {
            memcpy(enc_tmp.bf.B, enc_tmp.newAstr + i, aStrLen);
            memset(enc_tmp.bf.B + aStrLen, 0, AES_BLOCK_SIZE - aStrLen);
            aStrLen = 0;
            /* reset the mstring index */
            mStrIndex = 0;
        } else if ( mStrLen >= AES_BLOCK_SIZE ) {
            memcpy(enc_tmp.bf.B, mStr + mStrIndex * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
            mStrIndex++;
            mStrLen -= AES_BLOCK_SIZE;
        } else {
            memcpy(enc_tmp.bf.B, mStr + mStrIndex * AES_BLOCK_SIZE, mStrLen);
            memset(enc_tmp.bf.B + mStrLen, 0, AES_BLOCK_SIZE - mStrLen);
        }
    }

    memcpy(result, enc_tmp.tmpResult, micLen);
    
    return 0;
}

static uint8_t aes_ccmDecAuthTran(uint8_t micLen, uint8_t *key, uint8_t *nonce,
	uint8_t *mStr, uint16_t mStrLen, uint8_t *aStr, uint8_t aStrLen, uint8_t *mic)
{
    uint8_t tmpMic[AES_BLOCK_SIZE];
    uint8_t i;
    aes_ccmAuthTran(micLen, key, nonce, mStr, mStrLen, aStr, aStrLen, tmpMic);
    for (i = 0; i < micLen; i++ ) {
        if ( mic[i] != tmpMic[i] ) {
            return 1;
        }
    }
    return 0;
}


int aes_ccm_encrypt_debug(uint8_t* pPlainTxt, size_t textLen, uint8_t* pCipTxt, uint8_t* pKey, uint8_t* nonce)
{
    uint8_t aStr = 0x11;
    uint8_t mic[4] = {0};

    NRF_LOG_INFO("Plain Text:\r\n");
	NRF_LOG_HEXDUMP_INFO(pPlainTxt, textLen);
    
    aes_ccmAuthTran(4, pKey, nonce, pPlainTxt, textLen, &aStr, 1, mic);
    aes_ccmEncTran(4, pKey, nonce, pPlainTxt, textLen, &aStr, 1, mic);

    memcpy(pCipTxt, pPlainTxt, textLen);

    NRF_LOG_INFO("Cipher Text:\r\n");
	NRF_LOG_HEXDUMP_INFO(pCipTxt, textLen);

    NRF_LOG_INFO("MIC:\r\n");
    NRF_LOG_HEXDUMP_INFO(mic, 4);

    return 0;
}

uint8_t aes_ccm_encrypt_raw(
	uint8_t *key, uint8_t *nonce,
	uint8_t *aStr, uint8_t aStr_len,
	uint8_t *mic,  uint8_t micLen,
	uint8_t *mStr, uint8_t mStrLen)
{
	if ( aStr_len > 30 )
		return AES_FAIL;

    aes_ccmAuthTran(micLen, key, nonce, mStr, mStrLen, aStr, aStr_len, mic);
    aes_ccmEncTran(micLen, key, nonce, mStr, mStrLen, aStr, aStr_len, mic);

    return AES_SUCC;
}

uint8_t aes_ccm_decrypt_raw(
	uint8_t *key, uint8_t *nonce,
	uint8_t *aStr, uint8_t aStr_len,
	uint8_t *mic,  uint8_t micLen,
	uint8_t *mStr, uint8_t mStrLen)
{
	if ( aStr_len > 30 )
		return AES_FAIL;

    aes_ccmDecTran(micLen, key, nonce, mStr, mStrLen, aStr, aStr_len, mic);
    uint8_t res = aes_ccmDecAuthTran(micLen, key, nonce, mStr, mStrLen, aStr, aStr_len, mic);

    if ( res == 0 ) {
        return AES_SUCC;
    }
    return AES_FAIL;
}

uint8_t aes_ccm_encrypt(
	uint8_t *key, uint8_t *nonce,
	uint8_t *aStr, uint8_t aStr_len,
	uint8_t *mic,  uint8_t micLen,
	uint8_t *mStr, uint8_t mStrLen, uint8_t *result)
{
	if ( aStr_len > 30 )
		return AES_FAIL;

	uint8_t buf[mStrLen];
	memcpy(buf, mStr, mStrLen);
    aes_ccmAuthTran(micLen, key, nonce, buf, mStrLen, aStr, aStr_len, mic);
    aes_ccmEncTran(micLen, key, nonce, buf, mStrLen, aStr, aStr_len, mic);

    memcpy(result, buf, mStrLen);
    return AES_SUCC;
}

uint8_t aes_ccm_decrypt(
	uint8_t *key, uint8_t *nonce,
	uint8_t *aStr, uint8_t aStr_len,
	uint8_t *mic,  uint8_t micLen,
	uint8_t *mStr, uint8_t mStrLen, uint8_t *result)
{
	if ( aStr_len > 30 )
		return AES_FAIL;

	uint8_t buf[mStrLen];
	memcpy(buf, mStr, mStrLen);
    aes_ccmDecTran(micLen, key, nonce, buf, mStrLen, aStr, aStr_len, mic);
    uint8_t res = aes_ccmDecAuthTran(micLen, key, nonce, buf, mStrLen, aStr, aStr_len, mic);

    if ( res == 0 ) {
		memcpy(result, buf, mStrLen);
        return AES_SUCC;
    }
    return AES_FAIL;
}

void aes_ecb_test(void)
{
    uint8_t p[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t k[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t c[32] = {0};

    NRF_LOG_INFO("Plain Text:\n");
    NRF_LOG_HEXDUMP_INFO(p, sizeof(p));

    nrf_aes_ecb_encrypt(k, p, c);

    NRF_LOG_INFO("Cipher Text:\n");
    NRF_LOG_HEXDUMP_INFO(c, 16);
}

#define LEN 32
void aes_ccm_test(void)
{
    uint8_t k[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t nonce[13] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c};
    uint8_t p[64] = "HELLOWORLD!@#$%^helloworld123456";
    uint8_t c[64] = {0};
	uint8_t d[64] = {0};
    uint8_t  mic[4] = {0};
	uint8_t astr[4] = {1,2,3,4};

    aes_ccm_encrypt(k, nonce, astr, sizeof(astr), mic, 4, p, LEN, c);
	aes_ccm_decrypt(k, nonce, astr, sizeof(astr), mic, 4, c, LEN, d);

//    NRF_LOG_INFO("Clear Text:\r\n");
//    NRF_LOG_HEXDUMP_INFO(p, LEN);
    NRF_LOG_INFO("Cipher Text:\r\n");
    NRF_LOG_HEXDUMP_INFO(c, LEN);

	NRF_LOG_INFO("AES128-CCM TEST: ");
	if(memcmp(d, p, LEN) == 0) {
		NRF_LOG_RAW_INFO(" PASS \n");
	}
	else {
		NRF_LOG_RAW_INFO(" FAIL \n");
	}
	
}


