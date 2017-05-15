#include <stdint.h>
#include "app_timer.h"
#include "pt.h"
#include "ble_mi_secure.h"
#include "mi_secure.h"
#include "nrf_drv_twi.h"
#include "nrf_gpio.h"
#include "app_util.h"

#define NRF_LOG_MODULE_NAME "schd"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

#include "sha256.h"
#include "aes_ccm.h"
#include "mi_secure.h"
typedef struct {
	uint8_t dev_key[16];
	uint8_t app_key[16];
	uint8_t reserve[32];
} session_key_t;

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

APP_TIMER_DEF(mi_schd_timer_id);

#define PROFILE_PIN  25

#define MSC_XFER(CMD, PARA, PARAL, DATA, DATAL)                                \
(msc_xfer_control_block_t) {    .cmd = CMD,                                    \
								.p_para   = PARA,                              \
								.para_len = PARAL,                             \
								.p_data   = DATA,                              \
								.data_len = DATAL }

extern uint32_t auth_status;
ble_gap_addr_t dev_mac;
uint8_t app_pub[64];
uint8_t msc_info[12];
uint8_t dev_pub[64];
uint8_t dev_sha[32];
uint8_t shared_key[32];
session_key_t session_key;
uint8_t dev_sign[64];
uint8_t LTMK[32];
mbedtls_sha256_context sha256_ctx;

uint8_t msg_mic[4];
uint8_t enc_msg[64+4];


static uint8_t iv[13] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                         0x19, 0x1a, 0x1b, 0x1c};

msc_info_t tmp_info;

struct {
	uint16_t dev;
	uint16_t manu;
	uint16_t root;
} m_certs_len;

uint8_t dev_cert[512];
uint8_t manu_cert[512];

const uint8_t reg_salt[] = "smartcfg-setup-salt";
const uint8_t log_salt[] = "smartcfg-setup-salt";
const uint8_t share_salt[] = "smartcfg-setup-salt";
const uint8_t reg_info[] = "smartcfg-setup-info";
// Pseduo Timer
typedef struct {
	int start;
	int interval;
} timer_t;

static int schd_time;
static uint32_t  schd_interval = 64;
static pt_t mi_schd;
static pt_t pt1, pt2, pt3, pt4;

static int timer_expired(timer_t *t)
{ return (int)(schd_time - t->start) >= (int)t->interval; }

static void timer_set(timer_t *t, int interval_ms)
{ t->interval = (interval_ms << 5) / schd_interval; t->start = schd_time; }


extern fast_xfer_t m_app_pub;

reliable_xfer_t reliable_control_block;

void mi_schedulor(void * p_context);

int mi_schedulor_init(uint32_t interval)
{
	int32_t errno;
	schd_interval = interval;
	errno = app_timer_create(&mi_schd_timer_id, APP_TIMER_MODE_REPEATED, mi_schedulor);
	APP_ERROR_CHECK(errno);

	nrf_gpio_cfg_output(PROFILE_PIN);
	nrf_gpio_pin_clear(PROFILE_PIN);
	return 0;
}

int mi_schedulor_start(uint32_t *p_context)
{
	int32_t errno;
	schd_time = 0;
	PT_INIT(&pt1);
	PT_INIT(&pt2);
	PT_INIT(&pt3);
	NRF_LOG_INFO("START\n");
	errno = app_timer_start(mi_schd_timer_id, schd_interval, p_context);
	APP_ERROR_CHECK(errno);
	return errno;
}

int mi_schedulor_stop(int type)
{
	int32_t errno;
	errno = app_timer_stop(mi_schd_timer_id);
	return errno;
}



static int fast_xfer_thread(pt_t *pt)
{
	PT_BEGIN(pt);

	while(1) {
		/* Wait until the other protothread has set its flag. */
		PT_WAIT_UNTIL(pt, m_app_pub.avail == 1);
		m_app_pub.avail = 0;
		NRF_LOG_INFO("PT1 recive %d bytes:\n", m_app_pub.full_len);
		NRF_LOG_RAW_HEXDUMP_INFO(m_app_pub.data+255-m_app_pub.full_len, m_app_pub.full_len);
		
		m_app_pub.curr_len = m_app_pub.full_len;
		m_app_pub.full_len = 255;
		PT_WAIT_UNTIL(pt, fast_xfer_send(&m_app_pub) == 0);
		m_app_pub.full_len = 0;

	}

	PT_END(pt);
}


uint16_t find_lost_sn(reliable_xfer_t *pxfer)
{
	static uint16_t checked_sn = 1;
	uint8_t (*p_pkg)[18] = (void*)pxfer->pdata;

	p_pkg += checked_sn - 1;
	while (((uint32_t*)p_pkg)[0] != 0) {
		checked_sn++;
		p_pkg++;
	}

	if (checked_sn > pxfer->amount) {
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
	
	while(sn <= pxfer->amount) {
		PT_WAIT_UNTIL(pt, reliable_xfer_data(pxfer, sn) == NRF_SUCCESS);
		sn++;
	}
	
	while(pxfer->mode == MODE_ACK && pxfer->type != A_SUCCESS) {
		PT_WAIT_UNTIL(pt, pxfer->curr_sn != 0 || pxfer->type == A_SUCCESS);
		if (pxfer->type == A_SUCCESS)
			break;
		PT_WAIT_UNTIL(pt, reliable_xfer_data(pxfer, pxfer->curr_sn) == NRF_SUCCESS);
		pxfer->curr_sn = 0;
	}

	PT_END(pt);
}

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
	if (pframe->sn == 0 && pframe->f.ctrl.mode == MODE_CMD) {
		fctrl_cmd_t cmd = (fctrl_cmd_t)pframe->f.ctrl.type;
		reliable_control_block.mode = MODE_CMD;
		reliable_control_block.type = cmd;
		switch (cmd) {
			case DEV_CERT:
				reliable_control_block.amount = *(uint16_t*)pframe->f.ctrl.arg;
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
	while(pframe->sn > 0 && pframe->sn < reliable_control_block.amount && !timer_expired(&rxd_timer)) {
		memcpy(reliable_control_block.pdata + (pframe->sn - 1) * 18, pframe->f.data, len-sizeof(pframe->sn));
		timer_set(&rxd_timer, 1000);
		PT_YIELD(pt);
	}
	
	if (pframe->sn == reliable_control_block.amount)
		memcpy(reliable_control_block.pdata + (pframe->sn - 1) * 18, pframe->f.data, len-sizeof(pframe->sn));
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
			memcpy(reliable_control_block.pdata + (sn - 1) * 18, pframe->f.data, len-sizeof(sn));
		}
	}

	rl_xfer_mode = 0;
	PT_END(pt);
}

static timer_t timeout_timer;
reliable_xfer_t *p_rx_config;
reliable_xfer_t *p_tx_config;

pt_t pt_r_rxd_thd;
int reliable_rxd_thread(pt_t *pt, reliable_xfer_t *pxfer, uint8_t data_type)
{
	PT_BEGIN(pt);

	/* Recive data */
	PT_WAIT_UNTIL(pt, pxfer->amount != 0 && pxfer->type == data_type);

	PT_WAIT_UNTIL(pt, reliable_xfer_ack(A_READY) == NRF_SUCCESS);

	timer_set(&timeout_timer, 10000);
	PT_WAIT_UNTIL(pt, pxfer->amount == pxfer->curr_sn || timer_expired(&timeout_timer));

	PT_SPAWN(pt, &pt_resend, pthd_resend(&pt_resend, pxfer));

	pxfer->status = RXFER_DONE;


	PT_END(pt);
}

pt_t pt_r_txd_thd;
int reliable_txd_thread(pt_t *pt, reliable_xfer_t *pxfer, uint8_t data_type)
{
	PT_BEGIN(pt);

	/* Send data. */
	PT_WAIT_UNTIL(pt, reliable_xfer_cmd(data_type, pxfer->amount) == NRF_SUCCESS);

	PT_WAIT_UNTIL(pt, pxfer->mode == MODE_ACK && pxfer->type == A_READY);

	PT_SPAWN(pt, &pt_send, pthd_send(&pt_send, pxfer));

	pxfer->amount = 0;

	PT_END(pt);
}

static int reliable_xfer_thread(pt_t *pt)
{
	PT_BEGIN(pt);

	while(1) {
		/* Recive data */
		PT_WAIT_UNTIL(pt, reliable_control_block.amount != 0);
		reliable_control_block.pdata = dev_cert;
		PT_WAIT_UNTIL(pt, reliable_xfer_ack(A_READY) == NRF_SUCCESS);

		timer_set(&timeout_timer, 10000);
		PT_WAIT_UNTIL(pt, reliable_control_block.amount == reliable_control_block.curr_sn || timer_expired(&timeout_timer));

		PT_SPAWN(pt, &pt_resend, pthd_resend(&pt_resend, &reliable_control_block));

		/* Send data. */
		PT_WAIT_UNTIL(pt, reliable_xfer_cmd(DEV_CERT, reliable_control_block.amount) == NRF_SUCCESS);

		PT_WAIT_UNTIL(pt, reliable_control_block.mode == MODE_ACK && reliable_control_block.type == A_READY);

		PT_SPAWN(pt, &pt_send, pthd_send(&pt_send, &reliable_control_block));

		reliable_control_block.amount = 0;
		/* And we loop. */
	}

	PT_END(pt);
}

int reg_thread(pt_t *pt)
{
	PT_BEGIN(pt);
	/*

	reliable_recv(m_app_pub, sizeof(m_app_pub));
	msc_read(dev_cert1);
	reliable_send(dev_cert1, sizeof(dev_cert1));
	msc_read(dev_cert2);
	reliable_send(dev_cert2, sizeof(dev_cert2));
	msc_read(dev_pub);
	reliable_send(dev_pub, sizeof(dev_pub));

	*/
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
	
	MSC_STORE      = 0x40,
	MSC_READ,
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
#define MSC_SCL    26

extern volatile bool m_twi0_xfer_done;
extern const nrf_drv_twi_t TWI0;

static nrf_drv_twi_xfer_desc_t twi0_xfer;
static uint8_t twi_buf[512];
msc_xfer_control_block_t msc_control_block;

uint8_t calc_data_xor(uint8_t *pdata, uint16_t len)
{
	uint8_t chk = 0;
	while(len--)
		chk ^= *pdata++;
	return chk;
}

int msc_encode_twi_buf(msc_xfer_control_block_t *p_cb)
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

int msc_decode_twi_buf(msc_xfer_control_block_t *p_cb)
{
	uint16_t len = (twi_buf[0]<<8) | twi_buf[1];        // contain data + status
	uint8_t  chk = calc_data_xor(twi_buf, 2+len);
	uint16_t data_len = len - sizeof(p_cb->status);

	if (chk != twi_buf[2+len]) {
		p_cb->status = -1;
		return 1;
	}
	
	if(data_len != p_cb->data_len) {
		NRF_LOG_ERROR("MSC return data len error.\n");
		p_cb->status = twi_buf[2+data_len];
	}

	if (p_cb->p_data != NULL);
		memcpy(p_cb->p_data, twi_buf+2, data_len);

	return 0;
}

uint8_t test[] = {0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
                  0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x00};
pt_t pt_msc_thd;
int msc_thread(pt_t *pt, msc_xfer_control_block_t *p_cb)
{
	uint32_t err_code;

	PT_BEGIN(pt);

	static timer_t  msc_timer;

	msc_encode_twi_buf(p_cb);

	/* 4 = 2bytes lengh + 1byte cmd + 1byte chk  */
	twi0_xfer = (nrf_drv_twi_xfer_desc_t)NRF_DRV_TWI_XFER_DESC_TX(MSC_ADDR, twi_buf, p_cb->para_len+4);
	m_twi0_xfer_done = false;
	err_code = nrf_drv_twi_xfer(&TWI0, &twi0_xfer, 0);
	APP_ERROR_CHECK(err_code);
	PT_WAIT_UNTIL(pt, m_twi0_xfer_done);

	NRF_LOG_INFO("Waiting...  @schd_time %d\n", schd_time);
	PT_WAIT_UNTIL(pt, nrf_gpio_pin_read(MSC_SCL));
	NRF_LOG_INFO("Ready now.  @schd_time %d\n", schd_time);
	
	/* 4 = 2bytes lengh + 1byte status + 1byte chk  */
	twi0_xfer = (nrf_drv_twi_xfer_desc_t)NRF_DRV_TWI_XFER_DESC_RX(MSC_ADDR, twi_buf, p_cb->data_len+4);
	m_twi0_xfer_done = false;
	err_code = nrf_drv_twi_xfer(&TWI0, &twi0_xfer, 0);
	APP_ERROR_CHECK(err_code);
	PT_WAIT_UNTIL(pt, m_twi0_xfer_done);
	
	msc_decode_twi_buf(p_cb);
	if (p_cb->status != 0) {
		NRF_LOG_ERROR("Error 0x%02X\n RETRY...\n", p_cb->status);
		PT_RESTART(pt);
	}

	NRF_LOG_INFO("Finish MSC cmd 0x%02X\n\n", p_cb->cmd);
	p_cb->cmd = NULL;

	PT_END(pt);
}

int reg_auth(pt_t *pt)
{
	PT_BEGIN(pt);
	
	PT_WAIT_UNTIL(pt, dev_pub[63] != NULL);

    #if (NRF_SD_BLE_API_VERSION == 3)
        sd_ble_gap_addr_get(&dev_mac);
    #else
        sd_ble_gap_address_get(&dev_mac);
    #endif

	mbedtls_sha256_init(&sha256_ctx);
	mbedtls_sha256_starts(&sha256_ctx, 0 );
	mbedtls_sha256_update(&sha256_ctx, msc_info,  sizeof(msc_info));
	mbedtls_sha256_update(&sha256_ctx, dev_mac.addr,  sizeof(dev_mac.addr));
	mbedtls_sha256_update(&sha256_ctx, dev_pub,  sizeof(dev_pub));
	mbedtls_sha256_finish(&sha256_ctx, dev_sha);

	PT_WAIT_UNTIL(pt, shared_key[31] != NULL);
	SHA256_HKDF(  shared_key,         sizeof(shared_key),
			(void *)reg_salt,         sizeof(reg_salt),
	        (void *)reg_info,         sizeof(reg_info),
	    (void *)&session_key,         sizeof(session_key));

	PT_WAIT_UNTIL(pt, dev_sign[63] != NULL);
	uint8_t astring = 0x11;
	nrf_aes_ccm_encrypt_raw(session_key.dev_key, iv, &astring, msg_mic, 4, dev_sign, 64, enc_msg);
	
	PT_WAIT_UNTIL(pt, auth_status != REG_START);
	
	if (auth_status == REG_SUCCESS) {
		NRF_LOG_INFO("Auth success.\n");
	}
	else {
		NRF_LOG_INFO("Auth failed.\n");
	}
	PT_WAIT_UNTIL(pt, 0);
	PT_END(pt);
}

int reg_ble(pt_t *pt)
{
	PT_BEGIN(pt);
	
	memset(&reliable_control_block, 0, sizeof(reliable_control_block));
	reliable_control_block.pdata = app_pub;
	PT_SPAWN(pt, &pt_r_rxd_thd, reliable_rxd_thread(&pt_r_rxd_thd, &reliable_control_block, DEV_PUBKEY));
	
	PT_WAIT_UNTIL(pt, dev_pub[63] != NULL);
	reliable_control_block.pdata  = msc_info;
	reliable_control_block.amount = CEIL_DIV(sizeof(msc_info) + sizeof(dev_pub), 18);
	reliable_control_block.last_bytes = (sizeof(msc_info) + sizeof(dev_pub)) % 18;
	PT_SPAWN(pt, &pt_r_txd_thd, reliable_txd_thread(&pt_r_txd_thd, &reliable_control_block, DEV_PUBKEY));
	
	PT_WAIT_UNTIL(pt, dev_cert[m_certs_len.dev-1] != dev_cert[m_certs_len.dev-2]);
	reliable_control_block.pdata  = dev_cert;
	reliable_control_block.amount = CEIL_DIV(m_certs_len.dev, 18);
	reliable_control_block.last_bytes = m_certs_len.dev % 18;
	PT_SPAWN(pt, &pt_r_txd_thd, reliable_txd_thread(&pt_r_txd_thd, &reliable_control_block, DEV_CERT));
	
	PT_WAIT_UNTIL(pt, manu_cert[m_certs_len.manu-1] != manu_cert[m_certs_len.manu-2]);
	reliable_control_block.pdata  = manu_cert;
	reliable_control_block.amount = CEIL_DIV(m_certs_len.manu, 18);
	reliable_control_block.last_bytes = m_certs_len.manu % 18;
	PT_SPAWN(pt, &pt_r_txd_thd, reliable_txd_thread(&pt_r_txd_thd, &reliable_control_block, DEV_MANU_CERT));
	
	PT_WAIT_UNTIL(pt, enc_msg[64] != NULL);
	reliable_control_block.pdata  = enc_msg;
	reliable_control_block.amount = CEIL_DIV(sizeof(enc_msg), 18);
	reliable_control_block.last_bytes = sizeof(enc_msg) % 18;
	PT_SPAWN(pt, &pt_r_txd_thd, reliable_txd_thread(&pt_r_txd_thd, &reliable_control_block, DEV_SIGNATURE));

	PT_WAIT_UNTIL(pt, 0);
	PT_END(pt);
}

int reg_msc(pt_t *pt)
{
	PT_BEGIN(pt);

	msc_control_block.cmd = MSC_INFO;
	msc_control_block.p_data = (void*)&tmp_info;
	msc_control_block.data_len = 26;
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	memcpy(msc_info+8, (uint8_t*)&tmp_info.sw_ver, 4);

	msc_control_block.cmd = MSC_ID;
	msc_control_block.p_data = msc_info;
	msc_control_block.data_len = 8;
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	msc_control_block.cmd = MSC_PUBKEY;
	msc_control_block.p_data = dev_pub;
	msc_control_block.data_len = sizeof(dev_pub);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	msc_control_block.cmd = MSC_CERTS_LEN;
	msc_control_block.p_data = (void*)&m_certs_len;
	msc_control_block.data_len = sizeof(m_certs_len);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	m_certs_len.dev  = __REV16(m_certs_len.dev);
	m_certs_len.manu = __REV16(m_certs_len.manu);
	
	msc_control_block.cmd = MSC_DEV_CERT;
	msc_control_block.p_data = (void*)dev_cert;
	msc_control_block.data_len = m_certs_len.dev;
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	msc_control_block.cmd = MSC_MANU_CERT;
	msc_control_block.p_data = (void*)manu_cert;
	msc_control_block.data_len = m_certs_len.manu;
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	PT_WAIT_UNTIL(pt, app_pub[63] != NULL);

	msc_control_block = MSC_XFER(MSC_ECDHE, app_pub, 64, shared_key, 32);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	PT_WAIT_UNTIL(pt, dev_sha[31] != dev_sha[30]);

	msc_control_block = MSC_XFER(MSC_SIGN, dev_sha, 32, dev_sign, 64);
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));
	
//	PT_WAIT_UNTIL(pt, LTMK[0] != NULL);

//	msc_control_block = MSC_XFER(MSC_STORE, dev_sha, 32, dev_sign, 64);
//	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	PT_WAIT_UNTIL(pt, 0);
	PT_END(pt);
}
void aes_ecb_test();
void aes_ccm_test();
int auth_log(pt_t *pt)
{
	PT_BEGIN(pt);

	msc_control_block = (msc_xfer_control_block_t) {
								.cmd = MSC_PUBKEY,
								.p_data  = dev_pub,
								.data_len = sizeof(dev_pub)
	};
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

//	msc_control_block = (msc_xfer_control_block_t) {
//								.cmd = MSC_PUBKEY,
//								.p_data  = app_pub,
//								.data_len = sizeof(app_pub)
//	};
//	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));

	msc_control_block = (msc_xfer_control_block_t) {
								.cmd = MSC_SIGN,
								.p_para  = dev_pub,
								.para_len = 32,
								.p_data  = app_pub,
								.data_len = 64
	};
	PT_SPAWN(pt, &pt_msc_thd, msc_thread(&pt_msc_thd, &msc_control_block));


//	nrf_gpio_pin_set(PROFILE_PIN);
//	aes_ccm_test();
//	nrf_gpio_pin_clear(PROFILE_PIN);


	PT_WAIT_UNTIL(pt, 0);
	PT_END(pt);
}

int auth_share(pt_t *pt)
{
	PT_BEGIN(pt);

	PT_END(pt);
} 



void reg_procedure()
{
	reg_msc(&pt1);
	reg_ble(&pt2);
	reg_auth(&pt3);
}

void mi_schedulor(void * p_context)
{
	schd_time++;
	uint32_t *p_auth_status = p_context;
	uint8_t auth_type = *p_auth_status & 0x30;
//	switch (auth_type) {
//		case REG_START:
			reg_procedure();
//			break;
//		case LOG_START:
//		case SHARED_LOG_START:
//			
//			break;
//	}
	
//	fast_xfer_thread(&pt1);
//	reliable_xfer_thread(&pt2);
//	auth_log(&pt3);
}
