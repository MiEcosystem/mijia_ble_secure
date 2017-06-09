#ifndef __MI_BEACON_H__
#define __MI_BEACON_H__
#include <stdint.h>

typedef struct {
	uint8_t				factory_new  :1;
	uint8_t				is_connect   :1;
	uint8_t				is_central   :1;
	uint8_t				is_encrypt   :1;

	uint8_t				mac_include  :1;
	uint8_t				cap_include  :1;
	uint8_t				evt_include  :1;
	uint8_t				manu_data_include    :1;
	uint8_t				manu_title_include   :1;

	uint8_t				bind_confirm :1;
	uint8_t				reserved     :1;
	uint8_t				secure_login :1;
	uint8_t				version      :4;
} mibeacon_frame_ctrl_t;

typedef struct {
	uint16_t type;
	uint8_t  data_len;
	uint8_t *pdata;
} mibeacon_event_t;

typedef struct {
        uint8_t connectable : 1;
        uint8_t centralable : 1;
        uint8_t encryptable : 1;
        uint8_t bondAbility : 2;
        uint8_t reserved    : 3;
} mibeacon_capability_t;

typedef struct {
	uint8_t data_len;
	uint8_t *pdata;
} mibeacon_manu_data_t;

typedef struct {
	mibeacon_frame_ctrl_t frame_ctrl;
	uint16_t                     pid;
	uint8_t               frame_cnt_lsb;
	uint8_t               *p_mac;
	mibeacon_capability_t *p_capability;
	mibeacon_event_t      *p_event;
	mibeacon_manu_data_t  *p_manu_data;
	mibeacon_manu_data_t  *p_manu_title;
} mi_service_data_t;


int mi_service_data_set(mi_service_data_t const * const input, uint8_t *output, uint8_t *output_len);

#endif  /* __MI_BEACON_H__ */ 


