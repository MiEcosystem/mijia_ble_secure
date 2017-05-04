#include <stdint.h>
#include "app_timer.h"
#include "pt.h"
#include "ble_mi_secure.h"
#include "mi_secure.h"
#define NRF_LOG_MODULE_NAME "schd"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

APP_TIMER_DEF(mi_schd_timer_id);

// Pseduo Timer
typedef struct {
	int start;
	int interval;
} timer;

static int schd_time;

static int timer_expired(timer *t)
{ return (int)(schd_time - t->start) >= (int)t->interval; }

static void timer_set(timer *t, int interval)
{ t->interval = interval; t->start = schd_time; }

static uint32_t  schd_interval = 64;
static pthread_t mi_schd;
static pthread_t pt1, pt2;

void mi_schedulor(void * p_context);

int mi_schedulor_init(uint32_t interval)
{
	int32_t errno;
	schd_interval = interval;
	NRF_LOG_INFO("START\n");
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


extern fast_xfer_t m_app_pub;
int fast_xfer_recive(fast_xfer_t *pxfer);
int fast_xfer_send(fast_xfer_t *pxfer);

static int protothread1(pthread_t *pt)
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


uint8_t cert_buffer[1024];
reliable_xfer_t m_cert = {.pdata = cert_buffer};
extern int reliable_xfer_ack(fctrl_ack_t ack, ...);
extern uint16_t find_lost_sn(reliable_xfer_t *pxfer);
pthread_t pt_resend, pt_send;

uint16_t find_lost_sn(reliable_xfer_t *pxfer)
{
	static uint16_t checked_sn = 1;
	uint8_t (*p_pkg)[18] = (void*)pxfer->pdata;

	p_pkg += checked_sn - 1;
	while (((uint16_t*)p_pkg)[0] != 0) {
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

static int pthread_resend(pthread_t *pt)
{
	PT_BEGIN(pt);

	static uint16_t sn;

	while(1) {
		sn = find_lost_sn(&m_cert);
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


int reliable_xfer_data(reliable_xfer_t *pxfer, uint16_t sn);

static int pthread_send(pthread_t *pt)
{
	PT_BEGIN(pt);

	static uint16_t sn;
	sn = 1;
	
	while(sn <= m_cert.amount) {
		PT_WAIT_UNTIL(pt, reliable_xfer_data(&m_cert, sn) == NRF_SUCCESS);
		sn++;
	}
	
	while(m_cert.mode == MODE_ACK && m_cert.type != A_SUCCESS) {
		PT_WAIT_UNTIL(pt, m_cert.curr_sn != 0 || m_cert.type == A_SUCCESS);
		if (m_cert.type == A_SUCCESS)
			break;
		PT_WAIT_UNTIL(pt, reliable_xfer_data(&m_cert, m_cert.curr_sn) == NRF_SUCCESS);
		m_cert.curr_sn = 0;
	}

	PT_END(pt);
}

static int protothread2(pthread_t *pt)
{
  PT_BEGIN(pt);

  while(1) {

    /* Recive data */
    PT_WAIT_UNTIL(pt, m_cert.amount != 0);
	
	PT_WAIT_UNTIL(pt, reliable_xfer_ack(A_READY) == NRF_SUCCESS);

	PT_WAIT_UNTIL(pt, m_cert.amount == m_cert.curr_sn);

	PT_SPAWN(pt, &pt_resend, pthread_resend(&pt_resend));


    /* Send data. */
	PT_WAIT_UNTIL(pt, reliable_xfer_cmd(DEV_CERT, m_cert.amount) == NRF_SUCCESS);
	
	PT_WAIT_UNTIL(pt, m_cert.mode == MODE_ACK && m_cert.type == A_READY);
	
	PT_SPAWN(pt, &pt_send, pthread_send(&pt_send));
	
	m_cert.amount = 0;
	memset(cert_buffer, 0, sizeof(cert_buffer));
    /* And we loop. */
  }
  PT_END(pt);
}

void mi_schedulor(void * p_context)
{
	schd_time++;
//	NRF_LOG_INFO(" Tick %d\n", schd_time);
	protothread1(&pt1);
	protothread2(&pt2);

}
