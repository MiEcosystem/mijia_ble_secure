#include <string.h>
#include "ccm.h"
#include "mi_type.h"
#include "mi_arch.h"
#include "mi_beacon.h"
#include "ble_mi_secure.h"
#include "ble_advdata.h"
#include "app_mailbox.h"
#include "app_timer.h"

#define NRF_LOG_MODULE_NAME "BEACON"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

#define EVT_MAX_SIZE 16

APP_MAILBOX_DEF(mibeacon_mailbox, 4, EVT_MAX_SIZE);
APP_TIMER_DEF(mibeacon_timer);

static uint8_t  frame_cnt;
static uint8_t  beacon_key[16] = "DUMMY KEY";
static uint8_t  m_beacon_timer_is_running;
static mibeacon_config_t m_beacon_data;

static struct {
	uint8_t  mac[6];
	uint16_t pid;
	uint8_t  cnt;
	uint8_t  rand[3];
} beacon_nonce;

void set_beacon_key(uint8_t *p_key)
{
	arch_dev_mac_get(beacon_nonce.mac, 6);
	memcpy(beacon_key, p_key, sizeof(beacon_key));
}

static int manu_data_encode(mibeacon_manu_data_t *p_manu, uint8_t *output)
{

	output[0] = p_manu->len;
	memcpy(output+1, p_manu->val, p_manu->len);
	
	return 0;
}

static int event_encode(mibeacon_event_t *p_event, uint8_t *output)
{
	output[0] = p_event->type;
	output[1] = p_event->type >> 8;
	output[2] = p_event->len;
	memcpy(output+3, p_event->val, p_event->len);
	return 0;
}

int mi_beacon_data_set(mibeacon_config_t const * const config, uint8_t *output, uint8_t *output_len)
{
	mibeacon_frame_ctrl_t *p_frame_ctrl = (void*)output;
	mibeacon_event_t *p_event;

	if (config == NULL) {
		*output_len = 0;
		return 1;
	}

	m_beacon_data = *config;

	/*  encode frame_ctrl and product_id */
	memcpy(output, (uint8_t*)config, 4);
	output     += 4;
	*output_len = 4;

	output[0] = (uint8_t) ++frame_cnt;
	output      += 1;
	*output_len += 1;

	if (config->p_mac != NULL)
	{
		p_frame_ctrl->mac_include = 1;
		memcpy(output, config->p_mac, BLE_MAC_LEN);

		output      += BLE_MAC_LEN;
		*output_len += BLE_MAC_LEN;
	}

	if (config->p_capability != NULL)
	{
		p_frame_ctrl->cap_include = 1;
		memcpy(output, config->p_capability, sizeof(*config->p_capability));
		output      += sizeof(*config->p_capability);
		*output_len += sizeof(*config->p_capability);
	}

	if (config->p_event != NULL)
	{
		p_frame_ctrl->evt_include = 1;
		p_event = (void*)output;
		event_encode(config->p_event, output);
		output      += 3 + config->p_event->len;
		*output_len += 3 + config->p_event->len;
	}

	if (config->p_manu_data != NULL)
	{
		p_frame_ctrl->manu_data_include = 1;
		manu_data_encode(config->p_manu_data, output);
		output      += 1 + config->p_manu_data->len;
		*output_len += 1 + config->p_manu_data->len;
	}

	if (config->p_manu_title != NULL)
	{
		p_frame_ctrl->manu_title_include = 1;
		manu_data_encode(config->p_manu_title, output);
		output      += 1 + config->p_manu_title->len;
		*output_len += 1 + config->p_manu_title->len;
	}

	if (p_frame_ctrl->is_encrypt == 1 ) {
		if (*output_len < 20) {
			beacon_nonce.pid = config->pid;
			beacon_nonce.cnt = frame_cnt;
			arch_rand_get(beacon_nonce.rand, 3);
			uint8_t mic[4];
			uint8_t aad = 0x11;

			NRF_LOG_RAW_INFO("Plain text:");
			NRF_LOG_HEXDUMP_INFO((uint8_t*)p_event, p_event->len + 3);
			NRF_LOG_RAW_INFO("Nonce:");
			NRF_LOG_HEXDUMP_INFO(&beacon_nonce, 12);
			NRF_LOG_RAW_INFO("Key:");
			NRF_LOG_HEXDUMP_INFO(beacon_key, 16);

			aes_ccm_encrypt_and_tag(beacon_key,
	                (uint8_t*)&beacon_nonce, sizeof(beacon_nonce),
	                                   &aad, sizeof(aad),
	                      (uint8_t*)p_event, p_event->len + 3,
	                      (uint8_t*)p_event,
	                                    mic, 4);

			memcpy(output, beacon_nonce.rand, 3);
			output += 3;

			memcpy(output, mic, sizeof(mic));
			*output_len += 3 + sizeof(mic);

			NRF_LOG_RAW_INFO("Cipher + MIC:");
			NRF_LOG_HEXDUMP_INFO((uint8_t*)p_event, p_event->len + 3);
		}
		else {
			return -1;
		}
	}

	return 0;
}

static void mibeacon_timer_handler(void * p_context)
{
	uint8_t item[EVT_MAX_SIZE] ={0};
	uint8_t adv_data[27] = {0};
	uint8_t adv_len = 0;
	uint32_t errno;

	errno = app_mailbox_get(&mibeacon_mailbox, item);

	if (errno != NRF_SUCCESS) {
		m_beacon_timer_is_running = false;
		app_timer_stop(mibeacon_timer);
		NRF_LOG_INFO("mibeacon event adv end.\n");
		
	} else {
		NRF_LOG_RAW_HEXDUMP_INFO(item, item[2]+3);
		m_beacon_timer_is_running = true;
		app_timer_start(mibeacon_timer, APP_TIMER_TICKS(3000, 0), NULL);

		mibeacon_config_t beacon_cfg = {0};
		beacon_cfg.frame_ctrl.version = 4;
		beacon_cfg.frame_ctrl.is_encrypt = 0;
		beacon_cfg.pid = m_beacon_data.pid;
		beacon_cfg.p_event = (void*)item;
		mi_beacon_data_set(&beacon_cfg, adv_data, &adv_len);

		ble_advdata_service_data_t serviceData;
		serviceData.service_uuid = BLE_UUID_MI_SERVICE;
		serviceData.data.size    = adv_len;
		serviceData.data.p_data  = adv_data;

		ble_advdata_t          scan_rsp;
		memset(&scan_rsp, 0, sizeof(scan_rsp));
		scan_rsp.p_service_data_array = &serviceData;
		scan_rsp.service_data_count = 1;

		NRF_LOG_INFO("mibeacon event adv ...\n");
		errno = ble_advdata_set(NULL, &scan_rsp);
		APP_ERROR_CHECK(errno);
	}
}

int mibeacon_event_push(evt_t type, uint8_t len, void *val)
{
	uint32_t errno;
	uint8_t item[EVT_MAX_SIZE];

	if (len > EVT_MAX_SIZE-3)
		return 1;

	item[0] = type;
	item[1] = type>>8;
	item[2] = len;
	memcpy(item+3, (uint8_t*)val, len);

	errno = app_mailbox_put(&mibeacon_mailbox, item);
	APP_ERROR_CHECK(errno);

	if (m_beacon_timer_is_running != true ) {
		errno = app_timer_start(mibeacon_timer, APP_TIMER_TICKS(10, 0), NULL);
		APP_ERROR_CHECK(errno);
	}

	return 0;
}

int mibeacon_init()
{
	int errno;

	app_mailbox_create(&mibeacon_mailbox);
	app_mailbox_mode_set(&mibeacon_mailbox, APP_MAILBOX_MODE_NO_OVERFLOW );
	
	errno = app_timer_create(&mibeacon_timer, APP_TIMER_MODE_SINGLE_SHOT, mibeacon_timer_handler);
	APP_ERROR_CHECK(errno);
	
	return 0;
}

#if 0

uint8_t adv_data[31];
uint8_t adv_data_len;

void mibeacon_test()
{
	uint8_t foo[] = "helloworld!";
	uint8_t mac[] = "123456";

	mibeacon_config_t data = {0};

	data.frame_ctrl.version = 4;
	data.frame_ctrl.secure_login = 1;
	data.pid = 0xBEEF;

	mibeacon_capability_t cap = {.connectable = 1 };
	mibeacon_event_t      evt = {.type = 0x1234, .len = 11};
	memcpy(evt.val, foo, evt.len);

	data.p_event = &evt;
	data.p_capability = &cap;
	data.p_mac = mac;

	mi_beacon_data_set(&data, adv_data, &adv_data_len);
	
}
#endif
