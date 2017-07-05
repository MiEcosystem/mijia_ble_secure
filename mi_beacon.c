#include <string.h>
#include "aes_ccm.h"
#include "mi_type.h"
#include "mi_arch.h"
#include "mi_beacon.h"



#include "nrf_log.h"
#include "nrf_log_ctrl.h"

static uint8_t  frame_cnt;
static uint8_t  beacon_key[16] = "DUMMY KEY";

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

	output[0] = p_manu->data_len;
	memcpy(output+1, p_manu->pdata, p_manu->data_len);
	
	return 0;
}

static int event_encode(mibeacon_event_t *p_event, uint8_t *output)
{

	output[0] = p_event->type;
	output[1] = p_event->type >> 8;
	output[2] = p_event->data_len;
	memcpy(output+3, p_event->pdata, p_event->data_len);
	
	return 0;
}

int mi_service_data_set(mi_service_data_t const * const input, uint8_t *output, uint8_t *output_len)
{
	mibeacon_frame_ctrl_t *p_frame_ctrl = (void*)output;

	if (input == NULL) {
		*output_len = 0;
		return 1;
	}
	/*  encode frame_ctrl and product_id */
	memcpy(output, (uint8_t*)input, 4);
	*output_len = 4;
	output += 4;
	
	output[0] = (uint8_t) ++frame_cnt;
	output += 1;
	*output_len += 1;

	if (input->p_mac != NULL)
	{
		p_frame_ctrl->mac_include = 1;
		memcpy(output, input->p_mac, BLE_MAC_LEN);
		output     += BLE_MAC_LEN;
		*output_len += BLE_MAC_LEN;
	}
	
	if (input->p_capability != NULL)
	{
		p_frame_ctrl->cap_include = 1;
		memcpy(output, input->p_capability, sizeof(*input->p_capability));
		output     += sizeof(*input->p_capability);
		*output_len += sizeof(*input->p_capability);
	}

	if (input->p_event != NULL)
	{
		p_frame_ctrl->evt_include = 1;
		event_encode(input->p_event, output);
		output += 3 + input->p_event->data_len;
		*output_len += 3 + input->p_event->data_len;
	}

	if (input->p_manu_data != NULL)
	{
		p_frame_ctrl->manu_data_include = 1;
		manu_data_encode(input->p_manu_data, output);
		output += 1 + input->p_manu_data->data_len;
		*output_len += 1 + input->p_manu_data->data_len;
	}

	if (input->p_manu_title != NULL)
	{
		p_frame_ctrl->manu_title_include = 1;
		manu_data_encode(input->p_manu_title, output);
		output += 1 + input->p_manu_title->data_len;
		*output_len += 1 + input->p_manu_title->data_len;
	}

	if (p_frame_ctrl->is_encrypt == 1 ) {
		if (*output_len < 20) {
			beacon_nonce.pid = input->pid;
			beacon_nonce.cnt = frame_cnt;
			arch_rand_get(beacon_nonce.rand,   3);
			uint8_t mic[4];
			uint8_t aad = 0x11;

			NRF_LOG_RAW_INFO("Plain text:");
			NRF_LOG_HEXDUMP_INFO((uint8_t*)p_frame_ctrl + 5,*output_len - 5);
			NRF_LOG_RAW_INFO("Nonce:");
			NRF_LOG_HEXDUMP_INFO(&beacon_nonce,12);
			NRF_LOG_RAW_INFO("Key:");
			NRF_LOG_HEXDUMP_INFO(beacon_key,16);

			aes_ccm_encrypt(beacon_key, (uint8_t*)&beacon_nonce,
							&aad, sizeof(aad),
							mic,  sizeof(mic),
				(uint8_t*)p_frame_ctrl + 5, *output_len - 5, (uint8_t*)p_frame_ctrl + 5);

			memcpy(output, beacon_nonce.rand, 3);
			output += 3;
			memcpy(output, mic, sizeof(mic));

			*output_len += 3 + sizeof(mic);

			NRF_LOG_RAW_INFO("Cipher + MIC:");
			NRF_LOG_HEXDUMP_INFO((uint8_t*)p_frame_ctrl + 5, *output_len - 5);
		}
		else {
			return -1;
		}
	}

	return 0;
}

#if 0

uint8_t adv_data[31];
uint8_t adv_data_len;

void mibeacon_test()
{
	uint8_t foo[] = "helloworld!";
	uint8_t mac[] = "123456";

	mi_service_data_t data = {0};

	data.frame_ctrl.version = 4;
	data.frame_ctrl.secure_login = 1;
	data.pid = 0xBEEF;

	mibeacon_capability_t cap = {.connectable = 1 };
	mibeacon_event_t      evt = {.type = 0x1234, .data_len = 11, .pdata = foo};
	
	data.p_event = &evt;
	data.p_capability = &cap;
	data.p_mac = mac;

	mi_service_data_set(&data, adv_data, &adv_data_len);
	
}
#endif
