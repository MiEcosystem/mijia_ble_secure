#include <stdint.h>
#include <time.h>
#include "app_timer.h"
#include "pt.h"
#include "nrf_drv_twi_patched.h"
#include "nrf_gpio.h"
#include "app_util.h"

#define NRF_LOG_MODULE_NAME "SCHD"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

#include "sha256_hkdf.h"
#include "ccm.h"
#include "mi_secure.h"
#include "ble_mi_secure.h"
#include "mi_crypto.h"

#if defined(__CC_ARM)
  #pragma anon_unions
#elif defined(__ICCARM__)
  #pragma language=extended
#elif defined(__GNUC__)
  /* anonymous unions are enabled by default */
#endif

typedef struct {
    uint8_t  vid;
    uint16_t hw_ver;
    uint16_t sw_ver;
    uint16_t protocol_ver;
    uint8_t  cfg;
    uint8_t  reserve[2];
    uint16_t sn[16];
	uint8_t  pad[2];
} msc_info_t;

typedef struct {
	uint32_t expire_time;
	uint32_t key_id;
	uint32_t reserved;
} shared_key_t;

APP_TIMER_DEF(mi_schd_timer_id);

#define PRINT_MSC_INFO     0
#define PRINT_MAC          0
#define PRINT_DEV_PUBKEY   0
#define PRINT_SHA256       0
#define PRINT_SIGN         0

#define PROFILE_PIN        25
#define DATA_IS_VAILD(x,n)   ((x[n-1] != 0) && (x[n-2] != 0))
#define DATA_IS_INVAILD(x,n) (x[n-1] = x[n-2] = 0)

#define MSC_XFER(CMD, INPUT, INPUT_L, OUTPUT, OUTPUT_L)                         \
(msc_xfer_control_block_t) {    .cmd      = CMD,                                \
                                .p_para   = INPUT,                              \
                                .para_len = INPUT_L,                            \
                                .p_data   = OUTPUT,                             \
                                .data_len = OUTPUT_L }

#define SET_DATA_VAILD(x)        (x = 1)
#define SET_DATA_INVAILD(x)      (x = 0)
#define DATA_IS_VAILD_P(x)       (x == 1)
#define DATA_IS_INVAILD_P(x)     (x == 0)

static struct {
	uint8_t app_pub    :1 ;
	uint8_t dev_pub    :1 ;
	uint8_t msc_info   :1 ;
	uint8_t dev_sha    :1 ;
	uint8_t shared_key :1 ;
	uint8_t LTMK       :1 ;
	uint8_t session_key:1 ;
	uint8_t dev_sign   :1 ;

	uint8_t MKPK       :1 ;
	uint8_t encrypt_data :1 ;
	uint8_t login_encrypt_data :1 ;
	uint8_t shared_info :1 ;
} flags;

uint8_t app_pub[64];
uint8_t msc_info[12];
uint8_t dev_pub[64];
uint8_t dev_sha[32];
uint8_t shared_key[32];
uint8_t LTMK[32];
session_key_t session_key;
uint8_t dev_sign[64];

struct {
	uint8_t id;
	uint8_t cipher[32];
	uint8_t mic[4];
	uint8_t pad[3];
} MKPK;

struct {
	uint8_t cipher[64];
	uint8_t mic[4];
} encrypt_data;

uint32_t login_encrypt_data[2];

struct {
	union {
		uint8_t cipher[sizeof(shared_key_t)];
		shared_key_t key;
	};
	uint8_t mic[4];
} shared_info;

struct {
	uint8_t cipher[sizeof(shared_info)];
	uint8_t mic[4];
} encrypt_share_info;

uint8_t rand_key[16];

static uint8_t nonce[12] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                         0x19, 0x1a, 0x1b};

msc_info_t tmp_info;
struct {
	uint8_t pt1 :1;
	uint8_t pt2 :1;
	uint8_t pt3 :1;
	uint8_t reserve: 5;
} pt_flags;
struct {
	uint16_t dev;
	uint16_t manu;
	uint16_t root;
} m_certs_len;

uint8_t dev_cert[512];
uint8_t manu_cert[512];

const uint8_t reg_salt[] = "smartcfg-setup-salt";
const uint8_t reg_info[] = "smartcfg-setup-info";
const uint8_t log_salt[] = "smartcfg-login-salt";
const uint8_t log_info[] = "smartcfg-login-info";
const uint8_t share_salt[] = "smartcfg-share-salt";
const uint8_t share_info[] = "smartcfg-share-info";
const uint8_t mk_salt[] = "smartcfg-masterkey-salt";
const uint8_t mk_info[] = "smartcfg-masterkey-info";

// Pseduo Timer
typedef struct {
	int start;
	int interval;
} timer_t;

static int schd_time;
static uint32_t schd_status;
static uint32_t  schd_interval = 64;
static pt_t pt1, pt2, pt3, pt4;

static int timer_expired(timer_t *t)
{ return (int)(schd_time - t->start) >= (int)t->interval; }

static void timer_set(timer_t *t, int interval_ms)
{ t->interval = (interval_ms << 5) / schd_interval; t->start = schd_time; }

extern fast_xfer_t fast_control_block;
extern reliable_xfer_t reliable_control_block;

void mi_scheduler(void * p_context);

int mi_scheduler_init(uint32_t interval)
{
	int32_t errno;
	schd_interval = interval;
	errno = app_timer_create(&mi_schd_timer_id, APP_TIMER_MODE_REPEATED, mi_scheduler);
	APP_ERROR_CHECK(errno);

	nrf_gpio_cfg_output(PROFILE_PIN);
	nrf_gpio_pin_clear(PROFILE_PIN);
	return 0;
}

int mi_scheduler_start(uint32_t auth_stat)
{
	int32_t errno;
	schd_time = 0;
	schd_status = auth_stat;

	PT_INIT(&pt1);
	PT_INIT(&pt2);
	PT_INIT(&pt3);
	PT_INIT(&pt4);

	memset((char*)&flags, 0, sizeof(flags));
	memset((char*)&pt_flags, 0xFF, sizeof(pt_flags));

	memset(app_pub, 0, 364);
	memset(&reliable_control_block, 0, sizeof(reliable_control_block));
	login_encrypt_data[1] = 0;

	NRF_LOG_WARNING("\nSTART %X\n\n", schd_status);
	errno = app_timer_start(mi_schd_timer_id, schd_interval, &schd_status);
	APP_ERROR_CHECK(errno);

	mi_scheduler(&schd_status);
	return errno;
}

int mi_scheduler_stop(int type)
{
	int32_t errno;
	errno = app_timer_stop(mi_schd_timer_id);
	APP_ERROR_CHECK(errno);
	schd_status = 0;
	return errno;
}

static int fast_xfer_test(pt_t *pt)
{
	PT_BEGIN(pt);

	while(1) {
		/* Recive data */
		PT_WAIT_UNTIL(pt, fast_control_block.avail == 1);
		fast_control_block.avail = 0;
		NRF_LOG_INFO("fast xfer recive %d bytes:\n", fast_control_block.full_len);
		NRF_LOG_RAW_HEXDUMP_INFO(fast_control_block.data+255-fast_control_block.full_len, fast_control_block.full_len);
		
		/* Send the recived data */
		fast_control_block.curr_len = fast_control_block.full_len;
		fast_control_block.full_len = 255;
		PT_WAIT_UNTIL(pt, fast_xfer_send(&fast_control_block) == 0);
		fast_control_block.full_len = 0;

	}

	PT_END(pt);
}


static uint16_t find_lost_sn(reliable_xfer_t *pxfer)
{
	static uint16_t checked_sn = 1;
	uint8_t (*p_pkg)[18] = (void*)pxfer->pdata;

	p_pkg += checked_sn - 1;
	while (((uint16_t*)p_pkg)[0] != 0 && checked_sn <= pxfer->rx_num) {
		checked_sn++;
		p_pkg++;
	}

	if (checked_sn > pxfer->rx_num) {
		checked_sn = 1;
		return 0;
	}
	else
		return checked_sn;

}

pt_t pt_resend;
static int pthd_resend(pt_t *pt, reliable_xfer_t *pxfer)
{
	PT_BEGIN(pt);

	static uint16_t sn;

	while(1) {
		sn = find_lost_sn(pxfer);
		if (sn == 0) {
			PT_WAIT_UNTIL(pt, reliable_xfer_ack(A_SUCCESS) == NRF_SUCCESS);
			PT_EXIT(pt);
		}
		else {
			NRF_LOG_ERROR("lost packet %d.\n", sn);
			PT_WAIT_UNTIL(pt, reliable_xfer_ack(A_LOST, sn) == NRF_SUCCESS);
			PT_WAIT_UNTIL(pt, pxfer->curr_sn == sn);
		}
	}

	PT_END(pt);
}


pt_t pt_send;
static int pthd_send(pt_t *pt, reliable_xfer_t *pxfer)
{
	PT_BEGIN(pt);

	static uint16_t sn;
	sn = 1;

	while(sn <= pxfer->tx_num) {
		PT_WAIT_UNTIL(pt, reliable_xfer_data(pxfer, sn) == NRF_SUCCESS);
		sn++;
	}
	
	while(pxfer->mode == MODE_ACK && pxfer->ack != A_SUCCESS) {
		PT_WAIT_UNTIL(pt, pxfer->curr_sn != 0 || pxfer->ack == A_SUCCESS);
		if (pxfer->ack == A_SUCCESS) {
			break;
		}
		else if(pxfer->curr_sn <= pxfer->tx_num) {
			PT_WAIT_UNTIL(pt, reliable_xfer_data(pxfer, pxfer->curr_sn) == NRF_SUCCESS);
		}
		pxfer->curr_sn = 0;
	}

	PT_END(pt);
}

#if 0
uint8_t rl_xfer_mode = 0; // idle:0  rx:1  tx:2   error:3
pt_t pt_rl_rx;
int rl_rxd_thread(pt_t *pt, reliable_xfer_frame_t *pframe, uint8_t len)
{
//	if (rl_xfer_mode != 1 || rl_xfer_mode)
//		PT_EXIT(pt);

	static timer_t rxd_timer;
	static uint16_t sn;

	PT_BEGIN(pt);
	rl_xfer_mode = 1;
	// exchange data head : data type + data pkg cnt
	if (pframe->sn == 0 && pframe->ctrl.mode == MODE_CMD) {
		fctrl_cmd_t cmd = (fctrl_cmd_t)pframe->ctrl.type;
		reliable_control_block.mode = MODE_CMD;
		reliable_control_block.type = cmd;
		switch (cmd) {
			case DEV_CERT:
				reliable_control_block.tx_num = *(uint16_t*)pframe->ctrl.arg;
				break;
			default:
				NRF_LOG_ERROR("Unkown reliable CMD.\n");
		}
	}
	else {
		rl_xfer_mode = 3;
		PT_EXIT(pt);
	}

//	APP Layer PT_WAIT_UNTIL(pt, reliable_xfer_ack(A_READY) == NRF_SUCCESS);
	timer_set(&rxd_timer, 1000);
	while(pframe->sn > 0 && pframe->sn < reliable_control_block.tx_num && !timer_expired(&rxd_timer)) {
		memcpy(reliable_control_block.pdata + (pframe->sn - 1) * 18, pframe->data, len-sizeof(pframe->sn));
		timer_set(&rxd_timer, 1000);
		PT_YIELD(pt);
	}
	
	if (pframe->sn == reliable_control_block.tx_num)
		memcpy(reliable_control_block.pdata + (pframe->sn - 1) * 18, pframe->data, len-sizeof(pframe->sn));
	else {
		rl_xfer_mode = 3;
		PT_EXIT(pt);
	}

// <!> BUG : if sd_ble_gatts_hvx has no TX packet for the ackonwleage
	while(1) {
		sn = find_lost_sn(&reliable_control_block);
		if (sn == 0) {
			reliable_xfer_ack(A_SUCCESS);
			break;
		}
		else {
			reliable_xfer_ack(A_LOST, sn);
			PT_WAIT_UNTIL(pt, pframe->sn == sn);
			memcpy(reliable_control_block.pdata + (sn - 1) * 18, pframe->data, len-sizeof(sn));
		}
	}

	rl_xfer_mode = 0;
	PT_END(pt);
}
#endif

static timer_t timeout_timer;
int format_rx_cb(reliable_xfer_t *pxfer, void *p_rxd, uint16_t rxd_bytes)
{
	pxfer->pdata = p_rxd;
	pxfer->max_rx_num = CEIL_DIV(rxd_bytes, 18);
	pxfer->last_bytes  = rxd_bytes % 18;
	return 0;
}

int format_tx_cb(reliable_xfer_t *pxfer, void *p_txd, uint16_t txd_bytes)
{
	pxfer->pdata = p_txd;
	pxfer->tx_num = CEIL_DIV(txd_bytes, 18);
	pxfer->last_bytes  = txd_bytes % 18;
	return 0;
}

pt_t pt_r_rxd_thd;
int reliable_rxd_thread(pt_t *pt, reliable_xfer_t *pxfer, uint8_t data_type)
{
	PT_BEGIN(pt);

	/* Recive data */
	pxfer->state = RXFER_WAIT_CMD;
	PT_WAIT_UNTIL(pt, pxfer->rx_num != 0 && pxfer->cmd == data_type);
	if (pxfer->rx_num <= pxfer->max_rx_num && pxfer->pdata != NULL) {
		PT_WAIT_UNTIL(pt, reliable_xfer_ack(A_READY) == NRF_SUCCESS);
		pxfer->state = RXFER_RXD;
	} else {
		PT_WAIT_UNTIL(pt, reliable_xfer_ack(A_CANCEL) == NRF_SUCCESS);
		pxfer->rx_num = 0;
		PT_RESTART(pt);
	}
	timer_set(&timeout_timer, 2000);
	PT_WAIT_UNTIL(pt, pxfer->rx_num == pxfer->curr_sn || timer_expired(&timeout_timer));

	PT_SPAWN(pt, &pt_resend, pthd_resend(&pt_resend, pxfer));

	pxfer->state = RXFER_DONE;
	pxfer->rx_num = 0;
	PT_END(pt);
}

pt_t pt_r_txd_thd;
int reliable_txd_thread(pt_t *pt, reliable_xfer_t *pxfer, uint8_t data_type)
{
	PT_BEGIN(pt);

	/* Send data. */
	PT_WAIT_UNTIL(pt, reliable_xfer_cmd(data_type, pxfer->tx_num) == NRF_SUCCESS);

	pxfer->state = RXFER_WAIT_ACK;
	PT_WAIT_UNTIL(pt, pxfer->mode == MODE_ACK && pxfer->ack == A_READY);

	PT_SPAWN(pt, &pt_send, pthd_send(&pt_send, pxfer));

	pxfer->state = RXFER_DONE;
	pxfer->tx_num = 0;
	PT_END(pt);
}

static int reliable_xfer_test(pt_t *pt)
{
	PT_BEGIN(pt);
	static uint16_t rx_amount = 0;
	while(1) {
		/* Recive data */
		PT_WAIT_UNTIL(pt, reliable_control_block.rx_num != 0);
		rx_amount = reliable_control_block.rx_num;
		reliable_control_block.pdata = dev_cert;
		PT_WAIT_UNTIL(pt, reliable_xfer_ack(A_READY) == NRF_SUCCESS);

		timer_set(&timeout_timer, 10000);
		PT_WAIT_UNTIL(pt, reliable_control_block.rx_num == reliable_control_block.curr_sn || timer_expired(&timeout_timer));

		PT_SPAWN(pt, &pt_resend, pthd_resend(&pt_resend, &reliable_control_block));

		/* Send data. */
		reliable_control_block.tx_num = rx_amount;
		PT_WAIT_UNTIL(pt, reliable_xfer_cmd(DEV_CERT, reliable_control_block.tx_num) == NRF_SUCCESS);

		PT_WAIT_UNTIL(pt, reliable_control_block.mode == MODE_ACK && reliable_control_block.ack == A_READY);

		PT_SPAWN(pt, &pt_send, pthd_send(&pt_send, &reliable_control_block));

		reliable_control_block.tx_num = 0;
		/* And we loop. */
	}

	PT_END(pt);
}


typedef enum {
	// Info
	MSC_INFO       = 0x01,
	MSC_ID,

	// Sign
	MSC_SIGN       = 0x10,
	MSC_VERIFY     = 0x11,

	MSC_ECDHE      = 0x14,

	MSC_DEV_CERT   = 0x20,
	MSC_MANU_CERT,
	MSC_ROOT_CERT,
	MSC_CERTS_LEN  = 0x28,

	MSC_PUBKEY     = 0x3B,
	
	MSC_WR_MKPK    = 0x40,
	MSC_RD_MKPK,
	MSC_ERASE,
	
	MSC_RANDOM     = 0x50,
	MSC_STATUS     = 0x52,

	MSC_AESCCM_ENC = 0x60,
	MSC_AESCCM_DEC,
} msc_cmd_t;

typedef struct {
	msc_cmd_t     cmd;
	uint16_t para_len;
	uint16_t data_len;
	uint8_t   *p_para;
	uint8_t   *p_data;
	uint8_t    status;
} msc_xfer_control_block_t;

#define MSC_ADDR   0x2A
#define MSC_SCL    28

extern volatile bool m_twi0_xfer_done;
extern const nrf_drv_twi_t TWI0;

static nrf_drv_twi_xfer_desc_t twi0_xfer;
static uint8_t twi_buf[512];
msc_xfer_control_block_t msc_control_block;

static uint8_t calc_data_xor(uint8_t *pdata, uint16_t len)
{
	uint8_t chk = 0;
	while(len--)
		chk ^= *pdata++;
	return chk;
}

static int msc_encode_twi_buf(msc_xfer_control_block_t *p_cb)
{
	uint16_t para_len = p_cb->p_para == NULL ? 0 : p_cb->para_len;
	uint16_t cmd_len  = para_len + sizeof(msc_cmd_t);

	if (para_len > 512) {
		NRF_LOG_ERROR("MSC para len error.\n");
		return 1;
	}
	
	twi_buf[0] = cmd_len >> 8;
	twi_buf[1] = cmd_len & 0xFF;
	twi_buf[2] = p_cb->cmd;

	memcpy(twi_buf+3, p_cb->p_para, para_len);
	
	twi_buf[3+para_len] = calc_data_xor(twi_buf, para_len + 3);
	
	return 0;
} 

static int msc_decode_twi_buf(msc_xfer_control_block_t *p_cb)
{
	uint16_t len = (twi_buf[0]<<8) | twi_buf[1];        // contain data + status
	uint8_t  chk = calc_data_xor(twi_buf, 2+len);
	uint16_t data_len = len - sizeof(p_cb->status);
	
	if (chk != twi_buf[2+len]) {
		p_cb->status = 255;
		return 1;
	}
	
	if(data_len != p_cb->data_len) {
		NRF_LOG_ERROR("MSC return data len error.\n");
	}

	p_cb->status = twi_buf[2+data_len];

	if (p_cb->p_data != NULL);
		memcpy(p_cb->p_data, twi_buf+2, data_len);
	
	return 0;
}

pt_t pt_msc_thd;
int msc_thread(pt_t *pt, msc_xfer_control_block_t *p_cb)
{
	uint32_t err_code;

	PT_BEGIN(pt);

	static uint8_t  retry_times = 0;
	msc_encode_twi_buf(p_cb);

	/* 4 = 2bytes lengh + 1byte cmd + 1byte chk  */
	twi0_xfer = (nrf_drv_twi_xfer_desc_t)NRF_DRV_TWI_XFER_DESC_TX(MSC_ADDR, twi_buf, p_cb->para_len+4);
	m_twi0_xfer_done = false;
	err_code = nrf_drv_twi_xfer(&TWI0, &twi0_xfer, 0);
	APP_ERROR_CHECK(err_code);
	PT_WAIT_UNTIL(pt, m_twi0_xfer_done);

	NRF_LOG_INFO("Waiting...  @ schd_time %d\n", schd_time);
	PT_WAIT_UNTIL(pt, nrf_gpio_pin_read(MSC_SCL));
	NRF_LOG_INFO("Ready now.  @ schd_time %d\n", schd_time);
	
	/* 4 = 2bytes lengh + 1byte status + 1byte chk  */
	twi0_xfer = (nrf_drv_twi_xfer_desc_t)NRF_DRV_TWI_XFER_DESC_RX(MSC_ADDR, twi_buf, p_cb->data_len+4);
	m_twi0_xfer_done = false;
	err_code = nrf_drv_twi_xfer(&TWI0, &twi0_xfer, 0);
	APP_ERROR_CHECK(err_code);
	PT_WAIT_UNTIL(pt, m_twi0_xfer_done);
	
	msc_decode_twi_buf(p_cb);
	if (p_cb->status != 0 ) {
		if (retry_times < 5) {
			retry_times++;
			NRF_LOG_ERROR("CMD 0x%02X Error 0x%02X\n RETRY...\n", p_cb->cmd, p_cb->status);
			PT_RESTART(pt);
		} else {
			retry_times = 0;
			NRF_LOG_ERROR("Cann't run MSC CMD 0x%02X\n", p_cb->cmd);
			/* Blocking here, 
			   TODO: add error status handler    */
			PT_WAIT_UNTIL(pt, 0);
		}
		
	}

	NRF_LOG_INFO("Finish MSC cmd 0x%02X\n\n", p_cb->cmd);
	p_cb->cmd = NULL;

	PT_END(pt);
}


int reg_auth(pt_t *pt)
{
	PT_BEGIN(pt);
	
	PT_WAIT_UNTIL(pt, DATA_IS_VAILD_P(flags.msc_info));

	ble_gap_addr_t   dev_mac;
	uint8_t          dev_mac_be[6];

	#if (NRF_SD_BLE_API_VERSION == 3)
        sd_ble_gap_addr_get(&dev_mac);
    #else
        sd_ble_gap_address_get(&dev_mac);
    #endif

	for (int i = 0; i<6; i++)
		dev_mac_be[i] = dev_mac.addr[5-i];

	mbedtls_sha256_context sha256_ctx;
	mbedtls_sha256_init(&sha256_ctx);
	mbedtls_sha256_starts(&sha256_ctx, 0 );
	mbedtls_sha256_update(&sha256_ctx, msc_info,    sizeof(msc_info));
	mbedtls_sha256_update(&sha256_ctx, dev_mac_be,  sizeof(dev_mac_be));
	mbedtls_sha256_update(&sha256_ctx, dev_pub,     sizeof(dev_pub));
	mbedtls_sha256_finish(&sha256_ctx, dev_sha);

#if (PRINT_MSC_INFO  == 1)
	NRF_LOG_RAW_INFO("MSC info\t");
	NRF_LOG_HEXDUMP_INFO(msc_info, 12);
#endif
#if (PRINT_MAC       == 1)
	NRF_LOG_RAW_INFO("MAC\t");
	NRF_LOG_HEXDUMP_INFO(dev_be, 6);
#endif
#if (PRINT_DEV_PUBKEY == 1)
	NRF_LOG_RAW_INFO("DEV_PUBKEY\t");
	NRF_LOG_HEXDUMP_INFO(dev_pub, 16);
#endif
#if (PRINT_SHA256     == 1)
	NRF_LOG_RAW_INFO("SHA256\t");
	NRF_LOG_HEXDUMP_INFO(dev_sha, 32);
#endif

	PT_WAIT_UNTIL(pt, DATA_IS_VAILD_P(flags.shared_key));
	sha256_hkdf(  shared_key,         sizeof(shared_key),
			(void *)reg_salt,         sizeof(reg_salt)-1,
	        (void *)reg_info,         sizeof(reg_info)-1,
	    (void *)&session_key,         sizeof(session_key));

	PT_WAIT_UNTIL(pt, DATA_IS_VAILD(dev_sign, 64));

	aes_ccm_encrypt_and_tag(session_key.dev_key, nonce, sizeof(nonce), NULL, 0,
	                        dev_sign, 64, encrypt_data.cipher, encrypt_data.mic, 4);

	PT_WAIT_UNTIL(pt, auth_recv() != REG_START);
	if (auth_recv() != REG_SUCCESS) {
		NRF_LOG_ERROR("Auth failed.\n");
		mi_scheduler_stop(REG_FAILED);
		PT_EXIT(pt);
	}

	while(rand_key[0] < 16) {
		sd_rand_application_bytes_available_get(rand_key);
		PT_YIELD(pt);
	}
	sd_rand_application_vector_get(rand_key, 16);

	sha256_hkdf(  shared_key,         sizeof(shared_key),
			(void *) mk_salt,         sizeof(mk_salt)-1,
	        (void *) mk_info,         sizeof(mk_info)-1,
	                    LTMK,         sizeof(LTMK));

//	aes_ccm_encrypt(rand_key, nonce, NULL, 0, MKPK.mic, 4, LTMK, 32, MKPK.cipher);
	
	// fs_store(rand_key);
	// log encrypt procedure
	
//	PT_WAIT_UNTIL(pt, 0);
	PT_END(pt);
}

int reg_ble(pt_t *pt)
{
	PT_BEGIN(pt);

	format_rx_cb(&reliable_control_block, app_pub, sizeof(app_pub));
	PT_SPAWN(pt, &pt_r_rxd_thd, reliable_rxd_thread(&pt_r_rxd_thd, &reliable_control_block, DEV_PUBKEY));
	SET_DATA_VAILD(flags.app_pub);
	NRF_LOG_INFO("app_pub recived "NRF_LOG_COLOR_CODE_BLUE"@ schd_time %d\n", schd_time);
	
	PT_WAIT_UNTIL(pt, DATA_IS_VAILD_P(flags.msc_info));
	format_tx_cb(&reliable_control_block, msc_info, sizeof(msc_info) + sizeof(dev_pub));
	PT_SPAWN(pt, &pt_r_txd_thd, reliable_txd_thread(&pt_r_txd_thd, &reliable_control_block, DEV_PUBKEY));
	NRF_LOG_INFO("dev_pub send "NRF_LOG_COLOR_CODE_BLUE"@ schd_time %d\n", schd_time);

	PT_WAIT_UNTIL(pt, DATA_IS_VAILD(dev_cert, m_certs_len.dev-2));
	format_tx_cb(&reliable_control_block, dev_cert, m_certs_len.dev);
	PT_SPAWN(pt, &pt_r_txd_thd, reliable_txd_thread(&pt_r_txd_thd, &reliable_control_block, DEV_CERT));
	NRF_LOG_INFO("dev_cert send "NRF_LOG_COLOR_CODE_BLUE"@ schd_time %d\n", schd_time);
	
	PT_WAIT_UNTIL(pt, DATA_IS_VAILD(manu_cert, m_certs_len.manu-2));
	format_tx_cb(&reliable_control_block, manu_cert, m_certs_len.manu);
	PT_SPAWN(pt, &pt_r_txd_thd, reliable_txd_thread(&pt_r_txd_thd, &reliable_control_block, DEV_MANU_CERT));
	NRF_LOG_INFO("manu_cert send "NRF_LOG_COLOR_CODE_BLUE"@ schd_time %d\n", schd_time);
	
	PT_WAIT_UNTIL(pt, DATA_IS_VAILD(encrypt_data.mic, 4));
	format_tx_cb(&reliable_control_block, &encrypt_data, sizeof(encrypt_data));
	PT_SPAWN(pt, &pt_r_txd_thd, reliable_txd_thread(&pt_r_txd_thd, &reliable_control_block, DEV_SIGNATURE));
	NRF_LOG_INFO("encrypt_data send "NRF_LOG_COLOR_CODE_BLUE"@ schd_time %d\n", schd_time);

	PT_END(pt);
}

int reg_msc(pt_t *pt)
{
	PT_BEGIN(pt);

	msc_control_block = MSC_XFER(MSC_PUBKEY, NULL, 0, dev_pub, sizeof(dev_pub));
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	msc_control_block = MSC_XFER(MSC_INFO, NULL, 0, (void*)&tmp_info, 26);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	memcpy(msc_info+8, (uint8_t*)&tmp_info.sw_ver, 4);

	msc_control_block = MSC_XFER(MSC_ID, NULL, 0, msc_info, 8);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	SET_DATA_VAILD(flags.msc_info);

	msc_control_block = MSC_XFER(MSC_CERTS_LEN, NULL, 0, (void*)&m_certs_len, sizeof(m_certs_len));
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	m_certs_len.dev  = __REV16(m_certs_len.dev);
	m_certs_len.manu = __REV16(m_certs_len.manu);
	
	msc_control_block = MSC_XFER(MSC_DEV_CERT, NULL, 0, dev_cert, m_certs_len.dev);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	msc_control_block = MSC_XFER(MSC_MANU_CERT, NULL, 0, manu_cert, m_certs_len.manu);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	PT_WAIT_UNTIL(pt, DATA_IS_VAILD_P(flags.app_pub));

	msc_control_block = MSC_XFER(MSC_ECDHE, app_pub, 64, shared_key, 32);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));
	SET_DATA_VAILD(flags.shared_key);

	PT_WAIT_UNTIL(pt, DATA_IS_VAILD(dev_sha, 32));

	msc_control_block = MSC_XFER(MSC_SIGN, dev_sha, 32, dev_sign, 64);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));
#if (PRINT_SIGN == 1)
	NRF_LOG_HEXDUMP_INFO(dev_sign, 64);
#endif	

#if ENC_LTMK
	PT_WAIT_UNTIL(pt, DATA_IS_VAILD(MKPK.mic, 4));
	
	MKPK.id = 0;

	msc_control_block = MSC_XFER(MSC_WR_MKPK, (void*)&MKPK, 1+32+4, NULL, 0);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));
#else
	PT_WAIT_UNTIL(pt, DATA_IS_VAILD(LTMK, 32));
	
	MKPK.id = 1;
	memcpy(MKPK.cipher, LTMK, 32);
	msc_control_block = MSC_XFER(MSC_WR_MKPK, (void*)&MKPK, 1+32, NULL, 0);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));
	
#endif
	
	PT_END(pt);
}

void reg_procedure()
{
	if (pt_flags.pt1 == 1)
		pt_flags.pt1 = PT_SCHEDULE(reg_msc(&pt1));

	if (pt_flags.pt2 == 1)
		pt_flags.pt2 = PT_SCHEDULE(reg_ble(&pt2));

	if (pt_flags.pt3 == 1)
		pt_flags.pt3 = PT_SCHEDULE(reg_auth(&pt3));
	
	if (pt_flags.pt1 == 0 &&
		pt_flags.pt2 == 0 &&
		pt_flags.pt3 == 0 )
	{
		mi_scheduler_stop(0);
	}
}

int login_auth(pt_t *pt)
{
	PT_BEGIN(pt);

#if ENC_LTMK
	PT_WAIT_UNTIL(pt, DATA_IS_VAILD(MKPK.mic, 4));
	aes_ccm_auth_decrypt(       rand_key,
	                               nonce,  sizeof(nonce),
	                                NULL,  0,
	                         MKPK.cipher,  sizeof(MKPK.cipher),
	                                LTMK,
	                            MKPK.mic,  4);

#else
	PT_WAIT_UNTIL(pt, DATA_IS_VAILD(LTMK, 32));
#endif
	PT_WAIT_UNTIL(pt, DATA_IS_VAILD(shared_key, 32));

	sha256_hkdf(  shared_key,         sizeof(shared_key) + sizeof(LTMK),
			(void *)log_salt,         sizeof(log_salt)-1,
	        (void *)log_info,         sizeof(log_info)-1,
	    (void *)&session_key,         sizeof(session_key));

	PT_WAIT_UNTIL(pt, DATA_IS_VAILD_P(flags.login_encrypt_data));

	uint8_t errno = 
	aes_ccm_auth_decrypt(session_key.app_key,
	                               nonce,  sizeof(nonce),
	                                NULL,  0,
               (void*)login_encrypt_data,  4,
	           (void*)login_encrypt_data,
	       (void*)(login_encrypt_data+1),  4);
	
//	login_encrypt_data[1] =  soft_crc32(dev_pub, 64, 0);
	login_encrypt_data[1] = *(uint32_t*)dev_pub;
//	NRF_LOG_HEXDUMP_INFO(shared_key, 64);
//	NRF_LOG_HEXDUMP_INFO(session_key.dev_key, 16);
	 
  	if(login_encrypt_data[0] == login_encrypt_data[1]) {
		NRF_LOG_INFO("LOG SUCCESS.\n");
		PT_WAIT_UNTIL(pt, auth_send(LOG_SUCCESS) == NRF_SUCCESS);

		mi_encrypt_init(&session_key);
		mi_scheduler_stop(LOG_SUCCESS);
	}
	else {
		NRF_LOG_ERROR("LOG FAILED.%d\n", errno);
		PT_WAIT_UNTIL(pt, auth_send(LOG_FAILED) == NRF_SUCCESS);
		mi_scheduler_stop(LOG_FAILED);

	}

	// log success
	PT_END(pt);
}

int login_ble(pt_t *pt)
{
	PT_BEGIN(pt);
	
	format_rx_cb(&reliable_control_block, app_pub, sizeof(app_pub));
	PT_SPAWN(pt, &pt_r_rxd_thd, reliable_rxd_thread(&pt_r_rxd_thd, &reliable_control_block, DEV_PUBKEY));
	SET_DATA_VAILD(flags.app_pub);

	PT_WAIT_UNTIL(pt, DATA_IS_VAILD(dev_pub, 64));
	format_tx_cb(&reliable_control_block, dev_pub, sizeof(dev_pub));
	PT_SPAWN(pt, &pt_r_txd_thd, reliable_txd_thread(&pt_r_txd_thd, &reliable_control_block, DEV_PUBKEY));

	format_rx_cb(&reliable_control_block, login_encrypt_data, sizeof(login_encrypt_data));
	PT_SPAWN(pt, &pt_r_rxd_thd, reliable_rxd_thread(&pt_r_rxd_thd, &reliable_control_block, DEV_LOGIN_INFO));
	SET_DATA_VAILD(flags.login_encrypt_data);

	PT_END(pt);
}

int login_msc(pt_t *pt)
{
	PT_BEGIN(pt);

	msc_control_block = MSC_XFER(MSC_PUBKEY, NULL, 0, dev_pub, sizeof(dev_pub));
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

#if ENC_LTMK
	MKPK.id = 0;
	msc_control_block = MSC_XFER(MSC_RD_MKPK, &MKPK.id, 1, (uint8_t*)MKPK.cipher, 32+4);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));
#else
	MKPK.id = 1;
	msc_control_block = MSC_XFER(MSC_RD_MKPK, &MKPK.id, 1, (uint8_t*)LTMK, 32);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));
#endif

	PT_WAIT_UNTIL(pt, DATA_IS_VAILD_P(flags.app_pub));

	msc_control_block = MSC_XFER(MSC_ECDHE, app_pub, 64, shared_key, 32);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	PT_END(pt);
}


void login_procedure()
{
	if (pt_flags.pt1 == 1)
		pt_flags.pt1 = PT_SCHEDULE(login_msc(&pt1));

	if (pt_flags.pt2 == 1)
		pt_flags.pt2 = PT_SCHEDULE(login_ble(&pt2));

	if (pt_flags.pt3 == 1)
		pt_flags.pt3 = PT_SCHEDULE(login_auth(&pt3));
	
	if (pt_flags.pt1 == 0 &&
		pt_flags.pt2 == 0 &&
		pt_flags.pt3 == 0 )
	{
		mi_scheduler_stop(0);
	}

}

int shared_msc(pt_t *pt)
{
	PT_BEGIN(pt);

	MKPK.id = 0;
	msc_control_block = MSC_XFER(MSC_RD_MKPK, &MKPK.id, 1, (uint8_t*)MKPK.cipher, 32+4);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	msc_control_block = MSC_XFER(MSC_PUBKEY, NULL, 0, dev_pub, sizeof(dev_pub));
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	PT_WAIT_UNTIL(pt, app_pub[63] != app_pub[62]);
	msc_control_block = MSC_XFER(MSC_ECDHE, app_pub, 64, shared_key, 32);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));


	PT_WAIT_UNTIL(pt, 0);
	PT_END(pt);
}

int shared_ble(pt_t *pt)
{
	PT_BEGIN(pt);
	
	format_rx_cb(&reliable_control_block, app_pub, sizeof(app_pub));
	PT_SPAWN(pt, &pt_r_rxd_thd, reliable_rxd_thread(&pt_r_rxd_thd, &reliable_control_block, DEV_PUBKEY));
	
	PT_WAIT_UNTIL(pt, dev_pub[63] != dev_pub[62]);
	reliable_control_block.pdata  = dev_pub;
	reliable_control_block.tx_num = CEIL_DIV(sizeof(dev_pub), 18);
	reliable_control_block.last_bytes = sizeof(dev_pub) % 18;
	PT_SPAWN(pt, &pt_r_txd_thd, reliable_txd_thread(&pt_r_txd_thd, &reliable_control_block, DEV_PUBKEY));

	format_rx_cb(&reliable_control_block, &encrypt_share_info, sizeof(encrypt_share_info));
	PT_SPAWN(pt, &pt_r_rxd_thd, reliable_rxd_thread(&pt_r_rxd_thd, &reliable_control_block, DEV_SHARE_INFO));

	PT_WAIT_UNTIL(pt, 0);
	PT_END(pt);
}


#define  RTC_TIME_DRIFT  300
int verify_key(shared_key_t *pkey)
{
	time_t curr_time = time(NULL);

	if (curr_time <= pkey->expire_time + RTC_TIME_DRIFT)
		return 1;
	else
		return 0;
}

int shared_auth(pt_t *pt)
{
	PT_BEGIN(pt);
	// fs_read rand_key();
	PT_WAIT_UNTIL(pt, MKPK.mic[3] != 0);
	aes_ccm_auth_decrypt(rand_key,
	                               nonce,  sizeof(nonce),
	                                NULL,  0,
	                         MKPK.cipher,  sizeof(MKPK.cipher),
	                                LTMK,
	                            MKPK.mic,  4);

//	aes_ccm_decrypt(rand_key, nonce, NULL, 0, MKPK.mic, 4, MKPK.cipher, 32, LTMK);

	PT_WAIT_UNTIL(pt, shared_key[31] != shared_key[30]);
	sha256_hkdf(  shared_key,         sizeof(shared_key),
		  (void *)share_salt,         sizeof(share_salt)-1,
	      (void *)share_info,         sizeof(share_info)-1,
	    (void *)&session_key,         sizeof(session_key));

	PT_WAIT_UNTIL(pt, encrypt_share_info.mic[3] != 0);

	aes_ccm_auth_decrypt(session_key.app_key,
	                               nonce,  sizeof(nonce),
	                                NULL,  0,
	           encrypt_share_info.cipher,  sizeof(encrypt_share_info.cipher),
	                 (void*)&shared_info,
	              encrypt_share_info.mic,  sizeof(encrypt_share_info.mic));

	aes_ccm_auth_decrypt(LTMK,
	                               nonce,  sizeof(nonce),
	                                NULL,  0,
	                  shared_info.cipher,  sizeof(shared_info.cipher),
	                 (void*)&shared_info,
	                     shared_info.mic,  sizeof(shared_info.mic));

//	aes_ccm_decrypt(session_key.app_key, nonce, NULL, 0,
//					encrypt_share_info.mic,    sizeof(encrypt_share_info.mic),
//					encrypt_share_info.cipher, sizeof(encrypt_share_info.cipher),
//	                (void*)&shared_info);

//	aes_ccm_decrypt(LTMK, nonce, NULL, 0,
//					shared_info.mic,    sizeof(shared_info.mic),
//					shared_info.cipher , sizeof(shared_info.cipher),
//					(void*)&shared_info);
	
	if (verify_key(&shared_info.key) == false) {
		NRF_LOG_ERROR("SHARED LOG FAILED.\n");
		mi_scheduler_stop(SHARED_LOG_FAILED);
	}

	NRF_LOG_INFO("SHARED LOG SUCCESS.\n");
	PT_WAIT_UNTIL(pt, auth_send(SHARED_LOG_SUCCESS) == NRF_SUCCESS);
	
	// shared log success

	PT_WAIT_UNTIL(pt, 0);
	PT_END(pt);
}

void shared_login_procedure()
{
	shared_msc(&pt1);
	shared_ble(&pt2);
	shared_auth(&pt3);
}


#ifdef M_TEST
void aes_ecb_test();
void aes_ccm_test();
void aes_ccm_test2();
uint8_t test_str[] = {12, 1,2,3,4,5,6,7,8,9,0,1,2,
					   1, 0,
					  16, 0,'x',0xD,0xE,0xA,0xD,0xB,0xE,0xE,0xF,'a','b','c','d','e',30,
                      16, 1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6};

int test_thd(pt_t *pt)
{
	PT_BEGIN(pt);
	int i;

	uint8_t msg[] = "helloworld";
	uint8_t cipher[20];
	uint8_t plain[20] = {0};
	mi_encrypt_init((void*)&i);

	mi_session_encrypt(msg, 10, cipher);
	NRF_LOG_RAW_HEXDUMP_INFO(cipher, 16);

	mi_session_decrypt(cipher, 16, plain);
	NRF_LOG_RAW_HEXDUMP_INFO(plain, 10);
//	i = 1000;
//	nrf_gpio_pin_set(PROFILE_PIN);
//	while(i--)
//	aes_ccm_test();
//	nrf_gpio_pin_clear(PROFILE_PIN);
	
//	i = 1000;
//	nrf_gpio_pin_set(PROFILE_PIN);
//	while(i--)
//	aes_ccm_test2();
//	nrf_gpio_pin_clear(PROFILE_PIN);

//	i = 1;
//	nrf_gpio_pin_set(PROFILE_PIN);
//	while(i--)
//	sha256_hkdf(   test_str,          32,
//		  (void *)share_salt,         sizeof(share_salt)-1,
//	      (void *)share_info,         sizeof(share_info)-1,
//	    (void *)&session_key,         64);
//	nrf_gpio_pin_clear(PROFILE_PIN);
//	msc_control_block = MSC_XFER(MSC_AESCCM_ENC, test_str, sizeof(test_str), cipher, 20);
//	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));
//	NRF_LOG_HEXDUMP_INFO(cipher, 20);

//	PT_YIELD(pt);

	PT_WAIT_UNTIL(pt, 0);
	PT_END(pt);
}
#endif

void mi_scheduler(void * p_context)
{
	schd_time++;
	uint32_t *p_auth_status = p_context;
	uint8_t auth_type = *p_auth_status;
	
#ifdef M_TEST

//	fast_xfer_test(&pt1);
//	reliable_xfer_test(&pt2);
	test_thd(&pt3);

#else
	
	nrf_gpio_pin_set(PROFILE_PIN);

	switch (auth_type) {
		case REG_TYPE:
		case REG_SUCCESS:
		case REG_FAILED:
			reg_procedure();
			break;
		case LOG_TYPE:
			login_procedure();
			break;
		case SHARED_TYPE:
			shared_login_procedure();
			break;
	}
	
	nrf_gpio_pin_clear(PROFILE_PIN);

#endif

}
