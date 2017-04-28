#include <stdint.h>
#include "app_timer.h"
#include "pt.h"
#include "mi_secure.h"

#define NRF_LOG_MODULE_NAME "mi_secure"
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


static int protothread1_flag, protothread2_flag;


static int protothread1(pthread_t *pt)
{
	PT_BEGIN(pt);

	while(1) {
		/* Wait until the other protothread has set its flag. */
		PT_WAIT_UNTIL(pt, protothread2_flag != 0);
		NRF_LOG_INFO("Protothread 1 running\n");

		/* We then reset the other protothread's flag, and set our own
		   flag so that the other protothread can run. */
		protothread2_flag = 0;
		protothread1_flag = 1;

		/* And we loop. */
	}

	PT_END(pt);
}

static int protothread2(pthread_t *pt)
{
  PT_BEGIN(pt);

  while(1) {
    /* Let the other protothread run. */
    protothread2_flag = 1;

    /* Wait until the other protothread has set its flag. */
    PT_WAIT_UNTIL(pt, protothread1_flag != 0);
    NRF_LOG_INFO("Protothread 2 running\n");
    
    /* We then reset the other protothread's flag. */
    protothread1_flag = 0;

    /* And we loop. */
  }
  PT_END(pt);
}

void mi_schedulor(void * p_context)
{
	schd_time++;
	
	protothread1(&pt1);
	protothread2(&pt2);

}
