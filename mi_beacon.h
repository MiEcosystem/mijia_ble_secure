#ifndef __MI_BEACON_H__
#define __MI_BEACON_H__
#include <stdint.h>

typedef enum {
	GENERAL_EVT_BASE = 0x0000,
	CONNECT_EVT      = 0x0001,
	SIMPLE_PAIR_EVT  = 0x0002,
	LOCK_EVT         = 0x0005,

	GENERAL_STA_BASE = 0x1000,
	BUTTON_EVT       = 0x1001,
	SLEEP_EVT        = 0x1002,
	RSSI_EVT         = 0x1003,
	TEMPARATURE_EVT  = 0x1004,
	WATER_BOIL_EVT   = 0x1005,
	HUMIDITY_EVT     = 0x1006,
	LUMINA_EVT       = 0x1007,
	SOIL_PF_EVT      = 0x1008,
	SOIL_EC_EVT      = 0x1009,
	BATTERY_EVT      = 0x100A,

} evt_t;

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
	evt_t    type;
	uint8_t  len;
	uint8_t  val[20];
} mibeacon_event_t;

typedef struct {
	uint8_t connectable : 1;
	uint8_t centralable : 1;
	uint8_t encryptable : 1;
	uint8_t bondAbility : 2;
	uint8_t reserved    : 3;
} mibeacon_capability_t;

typedef struct {
	uint8_t len;
	uint8_t val[20];
} mibeacon_manu_data_t;

typedef struct {
	mibeacon_frame_ctrl_t frame_ctrl;
	uint16_t              pid;
	uint8_t               frame_cnt_lsb;
	uint8_t               *p_mac;
	mibeacon_capability_t *p_capability;
	mibeacon_event_t      *p_event;
	mibeacon_manu_data_t  *p_manu_data;
	mibeacon_manu_data_t  *p_manu_title;
} mibeacon_config_t;


int mi_beacon_data_set(mibeacon_config_t const * const in, uint8_t *out, uint8_t *out_len);
int mibeacon_event_push(evt_t evt, uint8_t len, void *val);
int mibeacon_init();


#endif  /* __MI_BEACON_H__ */ 


