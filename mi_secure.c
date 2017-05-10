#include <stdint.h>
#include "app_timer.h"
#include "pt.h"
#include "ble_mi_secure.h"
#include "mi_secure.h"
#include "nrf_drv_twi.h"
#include "nrf_gpio.h"
#define NRF_LOG_MODULE_NAME "schd"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

APP_TIMER_DEF(mi_schd_timer_id);

// Pseduo Timer
typedef struct {
	int start;
	int interval;
} timer_t;

static int schd_time;
static uint32_t  schd_interval = 64;
static pt_t mi_schd;
static pt_t pt1, pt2, pt3;

static int timer_expired(timer_t *t)
{ return (int)(schd_time - t->start) >= (int)t->interval; }

static void timer_set(timer_t *t, int interval_ms)
{ t->interval = (interval_ms << 5) / schd_interval; t->start = schd_time; }


extern fast_xfer_t m_app_pub;

uint8_t cert_buffer[1024];
reliable_xfer_t m_cert = {.pdata = cert_buffer};

void mi_schedulor(void * p_context);

int mi_schedulor_init(uint32_t interval)
{
	int32_t errno;
	schd_interval = interval;
	errno = app_timer_create(&mi_schd_timer_id, APP_TIMER_MODE_REPEATED, mi_schedulor);
	APP_ERROR_CHECK(errno);

	return 0;
}

int mi_schedulor_start(int type)
{
	int32_t errno;
	schd_time = 0;
	PT_INIT(&pt1);
	PT_INIT(&pt2);
	
	NRF_LOG_INFO("START\n");
	errno = app_timer_start(mi_schd_timer_id, schd_interval, NULL);
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

pt_t pt_resend, pt_send;

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

static int pthread_resend(pt_t *pt, reliable_xfer_t *pxfer)
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
			PT_WAIT_UNTIL(pt, m_cert.curr_sn == sn);
		}
	}

	PT_END(pt);
}



static int pthread_send(pt_t *pt, reliable_xfer_t *pxfer)
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

static timer_t timeout_timer;

static int reliable_xfer_thread(pt_t *pt)
{
	PT_BEGIN(pt);

	while(1) {
		/* Recive data */
		PT_WAIT_UNTIL(pt, m_cert.amount != 0);

		PT_WAIT_UNTIL(pt, reliable_xfer_ack(A_READY) == NRF_SUCCESS);

		timer_set(&timeout_timer, 10000);
		PT_WAIT_UNTIL(pt, m_cert.amount == m_cert.curr_sn || timer_expired(&timeout_timer));

		PT_SPAWN(pt, &pt_resend, pthread_resend(&pt_resend, &m_cert));

		/* Send data. */
		PT_WAIT_UNTIL(pt, reliable_xfer_cmd(DEV_CERT, m_cert.amount) == NRF_SUCCESS);

		PT_WAIT_UNTIL(pt, m_cert.mode == MODE_ACK && m_cert.type == A_READY);

		PT_SPAWN(pt, &pt_send, pthread_send(&pt_send, &m_cert));

		m_cert.amount = 0;
		memset(cert_buffer, 0, sizeof(cert_buffer));
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
} msc_xfer_cb_t;

#define MSC_ADDR   0x2A
#define MSC_SCL    26

extern volatile bool m_twi0_xfer_done;
extern const nrf_drv_twi_t TWI0;

static nrf_drv_twi_xfer_desc_t twi_xfer;

static uint8_t twi_buf[512];
msc_xfer_cb_t msc_xfer_cb;

uint8_t calc_data_xor(uint8_t *pdata, uint16_t len)
{
	uint8_t chk = 0;
	while(len--)
		chk ^= *pdata++;
	return chk;
}

int msc_encode_twi_buf(msc_xfer_cb_t *p_cb)
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

int msc_decode_twi_buf(msc_xfer_cb_t *p_cb)
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



int msc_thread(pt_t *pt, msc_xfer_cb_t *p_cb)
{
	uint32_t err_code;

	PT_BEGIN(pt);

	static timer_t  msc_timer;

	while(1) {

//		PT_WAIT_UNTIL(pt, p_cb->cmd != NULL);
		p_cb->cmd    = MSC_INFO;
		p_cb->p_para = NULL;
		p_cb->para_len = 0;
		p_cb->data_len = 26;

		msc_encode_twi_buf(p_cb);

		NRF_LOG_INFO("MCU ---cmd--> MSC.\n");
		/* 4 = 2bytes lengh + 1byte cmd + 1byte chk  */
  		twi_xfer = (nrf_drv_twi_xfer_desc_t)NRF_DRV_TWI_XFER_DESC_TX(MSC_ADDR, twi_buf, p_cb->para_len+4);
		m_twi0_xfer_done = false;
		err_code = nrf_drv_twi_xfer(&TWI0, &twi_xfer, 0);
		APP_ERROR_CHECK(err_code);
		PT_WAIT_UNTIL(pt, m_twi0_xfer_done);

		NRF_LOG_INFO("Waiting...  @schd_time %d\n", schd_time);
		PT_WAIT_UNTIL(pt, nrf_gpio_pin_read(MSC_SCL));
		NRF_LOG_INFO("Ready now.  @schd_time %d\n", schd_time);
		
		NRF_LOG_INFO("MSC ---data--> MCU.\n");
		/* 4 = 2bytes lengh + 1byte status + 1byte chk  */
		twi_xfer = (nrf_drv_twi_xfer_desc_t)NRF_DRV_TWI_XFER_DESC_RX(MSC_ADDR, twi_buf, p_cb->data_len+4);
		m_twi0_xfer_done = false;
		err_code = nrf_drv_twi_xfer(&TWI0, &twi_xfer, 0);
		APP_ERROR_CHECK(err_code);
		PT_WAIT_UNTIL(pt, m_twi0_xfer_done);
		
		msc_decode_twi_buf(&msc_xfer_cb);
		NRF_LOG_HEXDUMP_INFO(twi_buf, p_cb->data_len+4);

		NRF_LOG_INFO("Finish MSC cmd 0x%02X\n", p_cb->cmd);
		p_cb->cmd = NULL;

		PT_WAIT_UNTIL(pt, 0);
	}
	
	PT_END(pt);
}

void mi_schedulor(void * p_context)
{
	schd_time++;

	fast_xfer_thread(&pt1);
	reliable_xfer_thread(&pt2);
	msc_thread(&pt3, &msc_xfer_cb);
}
