/* Copyright (c) 2010-2017 Xiaomi. All Rights Reserved.
 *
 * The information contained herein is property of Xiaomi.
 * Terms and conditions of usage are described in detail in 
 * STANDARD SOFTWARE LICENSE AGREEMENT.
 *
 * Licensees are granted free, non-transferable use of the information. NO
 * WARRANTY of ANY KIND is provided. This heading must NOT be removed from
 * the file.
 *
 */
#include "sdk_common.h"
#include "ble_mi_secure.h"
#include "ble_srv_common.h"

#define NRF_LOG_MODULE_NAME "ble_mi"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

#define BLE_UUID_MI_AUTH   0x0010                      /**< The UUID of the AUTH   Characteristic. */
#define BLE_UUID_MI_BUFFER 0x0015                      /**< The UUID of the Buffer Characteristic. */
#define BLE_UUID_MI_PUBKEY 0x0016                      /**< The UUID of the PubKey Characteristic. */

#define PUBKEY_BYTE 255

typedef struct {
	uint8_t curr_len;
	uint8_t full_len;
	uint8_t avail;
	uint8_t data[PUBKEY_BYTE];
} fast_xfer_t;

typedef enum {
	PUBKEY = 0x10,
} fast_xfer_data_t;

typedef struct {
	uint8_t            remain_len;
	fast_xfer_data_t   type;
	uint8_t            data[1];
} fast_xfer_frame_t;

static void auth_handler(uint8_t *pdata, uint8_t len);
static void fast_xfer_rxd(fast_xfer_t *pxfer, uint8_t *pdata, uint8_t len);
static void buffer_rxd_handler(uint8_t *pdata, uint8_t len);

static ble_mi_t   mi_srv;

fast_xfer_t m_pubkey;

/**@brief Function for handling the @ref BLE_GAP_EVT_CONNECTED event from the S110 SoftDevice.
 *
 * @param[in] p_mi_s    Xiaomi Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_connect(ble_evt_t * p_ble_evt)
{
    mi_srv.conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
}


/**@brief Function for handling the @ref BLE_GAP_EVT_DISCONNECTED event from the S110 SoftDevice.
 *
 * @param[in] p_mi_s    Xiaomi Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_disconnect(ble_evt_t * p_ble_evt)
{
    UNUSED_PARAMETER(p_ble_evt);
    mi_srv.conn_handle = BLE_CONN_HANDLE_INVALID;
}


/**@brief Function for handling the @ref BLE_GATTS_EVT_WRITE event from the S110 SoftDevice.
 *
 * @param[in] p_mi_s    Xiaomi Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_write(ble_evt_t * p_ble_evt)
{
    ble_gatts_evt_write_t * p_evt_write = &p_ble_evt->evt.gatts_evt.params.write;

    if ((p_evt_write->len == 2) &&
		((p_evt_write->handle == mi_srv.auth_handles.cccd_handle)   ||
		 (p_evt_write->handle == mi_srv.pubkey_handles.cccd_handle) ||
		 (p_evt_write->handle == mi_srv.buffer_handles.cccd_handle)))
    {
        if (ble_srv_is_notification_enabled(p_evt_write->data))
        {
            mi_srv.is_notification_enabled = true;
        }
        else
        {
            mi_srv.is_notification_enabled = false;
        }
    }
    else if (p_evt_write->handle == mi_srv.auth_handles.value_handle)
    {
        auth_handler(p_evt_write->data, p_evt_write->len);
    }
    else if (p_evt_write->handle == mi_srv.buffer_handles.value_handle)
    {
        buffer_rxd_handler(p_evt_write->data, p_evt_write->len);
    }
    else if (p_evt_write->handle == mi_srv.pubkey_handles.value_handle)
    {
        if ( m_pubkey.avail != 1 )
			fast_xfer_rxd(&m_pubkey, p_evt_write->data, p_evt_write->len);
    }
    else
    {
        // Do Nothing. This event is not relevant for this service.
    }
}



/**@brief Function for adding the Characteristic.
 *
 * @param[in]   uuid           UUID of characteristic to be added. (BASE is BLE_TYPE)
 * @param[in]   p_char_value   Point to the characteristic to be added. When it's NULL,
 *                             the value will be store in STACK RAM. Otherwise, it will
 *                             store in USER RAM. (MUST be GLOBAL in RAM)
 * @param[in]   char_len       Length of initial value. This will also be the maximum value.
 * @param[in]   char_props     GATT Characteristic Properties.
 * @param[out]  p_handles      Handles of new characteristic.
 *
 * @return      NRF_SUCCESS on success, otherwise an error code.
 */
static uint32_t char_add(uint16_t                        uuid,
                         uint8_t                        *p_char_value,
                         uint16_t                        char_len,
                         ble_gatt_char_props_t           char_props,
                         ble_gatts_char_handles_t       *p_handles)
{
    ble_uuid_t          ble_uuid;
    ble_gatts_char_md_t char_md;
    ble_gatts_attr_t    attr_char_value;
    ble_gatts_attr_md_t attr_md;
    ble_gatts_attr_md_t cccd_md;

    // The ble_gatts_attr_md_t structure uses bit fields. So we reset the memory to zero.
    memset(&char_md, 0, sizeof(char_md));

    char_md.char_props = char_props;

    if (char_props.notify) {
		memset(&cccd_md, 0, sizeof(cccd_md));
		cccd_md.vloc         = BLE_GATTS_VLOC_STACK;
		BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.read_perm);
		BLE_GAP_CONN_SEC_MODE_SET_OPEN(&cccd_md.write_perm);
        char_md.p_cccd_md    = &cccd_md;
    } else {
        char_md.p_cccd_md    = NULL;
    }

    memset(&attr_md, 0, sizeof(attr_md));

	BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
	BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
    attr_md.vloc       = p_char_value == NULL ? BLE_GATTS_VLOC_STACK : BLE_GATTS_VLOC_USER;
    attr_md.rd_auth    = 0;
    attr_md.wr_auth    = 0;
    attr_md.vlen       = 0;

    BLE_UUID_BLE_ASSIGN(ble_uuid, uuid);

    memset(&attr_char_value, 0, sizeof(attr_char_value));

    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.init_len  = 1;
    attr_char_value.init_offs = 0;
    attr_char_value.max_len   = char_len;
    attr_char_value.p_value   = p_char_value ? p_char_value : NULL;

    return sd_ble_gatts_characteristic_add(mi_srv.service_handle,
	                                       &char_md,
	                                       &attr_char_value,
	                                       p_handles);
}

static void auth_handler(uint8_t *pdata, uint8_t len)
{
	return;
}

static void fast_xfer_rxd(fast_xfer_t *pxfer, uint8_t *pdata, uint8_t len)
{
	fast_xfer_frame_t *pframe = (fast_xfer_frame_t*)pdata;

	uint8_t          full_len = pxfer->full_len;
	uint8_t          curr_len = pframe->remain_len;
	uint8_t          data_len = len - 2;

	if ((pframe->remain_len < data_len)) {
		NRF_LOG_ERROR(" illegal frame parameter : len\n");
		pxfer->full_len = 0;
		return;
	}
	if (full_len < curr_len )
		pxfer->full_len = curr_len;

	memcpy(pxfer->data + sizeof(pxfer->data) - curr_len,
		   pframe->data,
		   data_len);

	pxfer->curr_len += data_len;

	if (pxfer->curr_len == pxfer->full_len )
		pxfer->avail = 1;
}

static void buffer_rxd_handler(uint8_t *pdata, uint8_t len)
{
	
}

void ble_mi_on_ble_evt(ble_evt_t * p_ble_evt)
{
    if (p_ble_evt == NULL)
    {
        return;
    }

    switch (p_ble_evt->header.evt_id)
    {
        case BLE_GAP_EVT_CONNECTED:
            on_connect(p_ble_evt);
            break;

        case BLE_GAP_EVT_DISCONNECTED:
            on_disconnect(p_ble_evt);
            break;

        case BLE_GATTS_EVT_WRITE:
            on_write(p_ble_evt);
            break;

		case BLE_EVT_TX_COMPLETE:
			break;

        default:
            // No implementation needed.
            break;
    }
}

uint32_t ble_mi_init(const ble_mi_init_t * p_mi_s_init)
{
    uint32_t      err_code;
    ble_uuid_t    ble_uuid;

//    VERIFY_PARAM_NOT_NULL(p_mi_s_init);

    // Initialize the service structure.
    mi_srv.conn_handle             = BLE_CONN_HANDLE_INVALID;
    mi_srv.data_handler            = p_mi_s_init->data_handler;
    mi_srv.is_notification_enabled = false;

    /**@snippet [Adding proprietary Service to S13x SoftDevice] */
    // Add a MI UUID.
	mi_srv.uuid_type = BLE_UUID_TYPE_BLE;
	BLE_UUID_BLE_ASSIGN(ble_uuid, BLE_UUID_MI_SERVICE);
    // Add the service.
    err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY,
                                        &ble_uuid,
                                        &mi_srv.service_handle);
    VERIFY_SUCCESS(err_code);

    // Add the AUTH Characteristic.
	ble_gatt_char_props_t char_props = {0};
	char_props.write_wo_resp         = 1;
	char_props.notify                = 1;
    err_code = char_add(BLE_UUID_MI_AUTH, NULL, 4, char_props, &mi_srv.auth_handles);
    VERIFY_SUCCESS(err_code);

    // Add the Buffer Characteristic.
	char_props = (ble_gatt_char_props_t){0};
	char_props.write_wo_resp         = 1;
	char_props.notify                = 1;
    err_code = char_add(BLE_UUID_MI_BUFFER, NULL, 20, char_props, &mi_srv.buffer_handles);
    VERIFY_SUCCESS(err_code);

	// Add the Pubkey Characteristic.
	char_props = (ble_gatt_char_props_t){0};
	char_props.write_wo_resp         = 1;
	char_props.notify                = 1;
	err_code = char_add(BLE_UUID_MI_PUBKEY, NULL, 20, char_props, &mi_srv.pubkey_handles);
    VERIFY_SUCCESS(err_code);
    
	return NRF_SUCCESS;
}

uint32_t ble_mi_string_send(uint8_t * p_string, uint16_t length)
{
    ble_gatts_hvx_params_t hvx_params;


    if ((mi_srv.conn_handle == BLE_CONN_HANDLE_INVALID) || (!mi_srv.is_notification_enabled))
    {
        return NRF_ERROR_INVALID_STATE;
    }

    if (length > BLE_MI_MAX_DATA_LEN)
    {
        return NRF_ERROR_INVALID_PARAM;
    }

    memset(&hvx_params, 0, sizeof(hvx_params));

    hvx_params.handle = mi_srv.buffer_handles.value_handle;
    hvx_params.p_data = p_string;
    hvx_params.p_len  = &length;
    hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;

    return sd_ble_gatts_hvx(mi_srv.conn_handle, &hvx_params);
}

