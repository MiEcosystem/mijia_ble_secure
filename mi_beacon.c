#include <string.h>
#include "ccm.h"

#include "nrf_queue.h"
#include "ble_advdata.h"
#include "app_mailbox.h"
#include "app_timer.h"

#include "mi_type.h"
#include "mi_error.h"
#include "mi_config.h"
#include "mi_arch.h"
#include "mi_beacon.h"

#define NRF_LOG_MODULE_NAME "BEACON"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

#define PRINT_ENC_CTX          0

typedef uint8_t mi_obj_element_t[EVT_MAX_SIZE];

APP_TIMER_DEF(mibeacon_timer);
NRF_QUEUE_DEF(mi_obj_element_t, mi_obj_queue, EVT_QUEUE_SIZE, NRF_QUEUE_MODE_NO_OVERFLOW);

static uint8_t  frame_cnt;
static uint8_t  beacon_key[16] = "DUMMY KEY";
static uint8_t  m_beacon_timer_is_running;
static uint8_t  m_beacon_key_is_vaild;

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
	m_beacon_key_is_vaild = 1;
}

static int manu_data_encode(mibeacon_manu_data_t *p_manu, uint8_t *output)
{
	output[0] = p_manu->len;
	memcpy(output+1, p_manu->val, p_manu->len);
	
	return 0;
}

static int event_encode(mibeacon_obj_t *p_obj, uint8_t *output)
{
	output[0] = p_obj->type;
	output[1] = p_obj->type >> 8;
	output[2] = p_obj->len;
	memcpy(output+3, p_obj->val, p_obj->len);
	return 0;
}

int mibeacon_data_set(mibeacon_config_t const * const config, uint8_t *output, uint8_t *output_len)
{
	mibeacon_frame_ctrl_t *p_frame_ctrl = (void*)output;
	mibeacon_obj_t *p_obj;

	if (config == NULL) {
		*output_len = 0;
		return MI_ERROR_INVALID_PARAM;
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

	if (config->p_obj != NULL)
	{
		p_frame_ctrl->evt_include = 1;
		p_obj = (void*)output;
		event_encode(config->p_obj, output);
		output      += 3 + config->p_obj->len;
		*output_len += 3 + config->p_obj->len;
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

	if (p_frame_ctrl->is_encrypt == 1) {
		if (*output_len < 20 && m_beacon_key_is_vaild) {
			beacon_nonce.pid = config->pid;
			beacon_nonce.cnt = frame_cnt;
			arch_rand_get(beacon_nonce.rand, 3);

			uint8_t mic[4];
			uint8_t aad = 0x11;
			uint8_t evt_len = p_obj->len+3;
	#if (PRINT_ENC_CTX == 1)
			NRF_LOG_RAW_INFO("Plain text:\n");
			NRF_LOG_RAW_HEXDUMP_INFO((uint8_t*)p_obj, evt_len);
			NRF_LOG_RAW_INFO("Nonce:\n");
			NRF_LOG_RAW_HEXDUMP_INFO(&beacon_nonce, 12);
			NRF_LOG_RAW_INFO("Key:\n");
			NRF_LOG_RAW_HEXDUMP_INFO(beacon_key, 16);
	#endif
			aes_ccm_encrypt_and_tag(beacon_key,
	                (uint8_t*)&beacon_nonce, sizeof(beacon_nonce),
	                                   &aad, sizeof(aad),
	                        (uint8_t*)p_obj, evt_len,
	                        (uint8_t*)p_obj,
	                                    mic, 4);

			memcpy(output, beacon_nonce.rand, 3);
			output += 3;

			memcpy(output, mic, sizeof(mic));
			*output_len += 3 + sizeof(mic);
	#if (PRINT_ENC_CTX == 1)
			NRF_LOG_RAW_INFO("Cipher:\n");
			NRF_LOG_RAW_HEXDUMP_INFO((uint8_t*)p_obj, evt_len);
			NRF_LOG_RAW_INFO("MIC:\n");
			NRF_LOG_RAW_HEXDUMP_INFO((uint8_t*)mic, 4);
	#endif
		} else {
			p_frame_ctrl->is_encrypt = 0;
			return MI_ERROR_NOT_INIT;
		}
	}

	return 0;
}

static void mibeacon_timer_handler(void * p_context)
{
	mi_obj_element_t elem = {0};
	uint8_t adv_data[27] = {0};
	uint8_t adv_len = 0;
	uint32_t errno;

	errno = nrf_queue_pop(&mi_obj_queue, elem);

	if (errno != NRF_SUCCESS) {
		m_beacon_timer_is_running = false;
		app_timer_stop(mibeacon_timer);
		sd_ble_gap_adv_data_set(NULL, 0, adv_data, 0);
		NRF_LOG_INFO("mibeacon event adv end.\n");
	} else {
		m_beacon_timer_is_running = true;
		app_timer_start(mibeacon_timer, APP_TIMER_TICKS(3000, 0), NULL);

		mibeacon_config_t beacon_cfg = {0};
		beacon_cfg.frame_ctrl.version = 4;
		beacon_cfg.frame_ctrl.is_encrypt = 1;
		beacon_cfg.pid = m_beacon_data.pid;
		beacon_cfg.p_obj = (void*)elem;
		mibeacon_data_set(&beacon_cfg, adv_data, &adv_len);
#if 0
		ble_advdata_service_data_t serviceData;
		serviceData.service_uuid = BLE_UUID_MI_SERVICE;
		serviceData.data.size    = adv_len;
		serviceData.data.p_data  = adv_data;

		ble_advdata_t          scan_rsp;
		memset(&scan_rsp, 0, sizeof(scan_rsp));
		scan_rsp.p_service_data_array = &serviceData;
		scan_rsp.service_data_count = 1;
#else
		ble_advdata_manuf_data_t manu_data;
		manu_data.company_identifier = BLE_COMPANY_ID_XIAOMI;
		manu_data.data.size          = adv_len;
		manu_data.data.p_data        = adv_data;

		ble_advdata_t          scan_rsp;
		memset(&scan_rsp, 0, sizeof(scan_rsp));
		scan_rsp.p_manuf_specific_data = &manu_data;
#endif
		NRF_LOG_INFO("mibeacon event adv ...\n");
		errno = ble_advdata_set(NULL, &scan_rsp);
		APP_ERROR_CHECK(errno);
	}
}

int mibeacon_obj_enque(mibeacon_obj_name_t evt, uint8_t len, void *val)
{
	uint32_t errno;
	mi_obj_element_t elem;

	if (len > EVT_MAX_SIZE-3)
		return MI_ERROR_DATA_SIZE;

	elem[0] = evt;
	elem[1] = evt >> 8;
	elem[2] = len;
	memcpy(elem+3, (uint8_t*)val, len);

	errno = nrf_queue_push(&mi_obj_queue, elem);
	if(errno != MI_SUCCESS) {
		NRF_LOG_ERROR("push beacon event errno %d\n", errno);
		return MI_ERROR_RESOURCES;
	}
	if (m_beacon_timer_is_running != true ) {
		/* All event will be processed in mibeacon_timer_handler() */
		errno = app_timer_start(mibeacon_timer, APP_TIMER_TICKS(10, 0), NULL);
		APP_ERROR_CHECK(errno);
	}

	return 0;
}

int mibeacon_init()
{
	int errno;
	
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

	mibeacon_config_t config = {0};

	config.frame_ctrl.version = 4;
	config.frame_ctrl.secure_login = 1;
	config.pid = 0xBEEF;

	mibeacon_capability_t cap = {.connectable = 1 };
	mibeacon_obj_t      evt = {.type = 0x1234, .len = 11};
	memcpy(evt.val, foo, evt.len);

	config.p_obj = &evt;
	config.p_capability = &cap;
	config.p_mac = mac;

	mibeacon_data_set(&config, adv_data, &adv_data_len);
	
}
#endif
