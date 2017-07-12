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
#include <stdarg.h>
#include "sdk_common.h"
#include "ble_srv_common.h"
#include "app_fifo.h"
#include "mi_secure.h"
#include "mi_crypto.h"

#include "ble_lock.h"

#define NRF_LOG_MODULE_NAME "LOCK"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

#define BLE_UUID_LOCK_SERVICE     0x1000

#define BLE_UUID_LOCK_OPERATION   0x1001                      /**< The UUID of the Operation Characteristic. */
#define BLE_UUID_LOCK_STATE       0x1002                      /**< The UUID of the Lock current state Characteristic. */
#define BLE_UUID_LOCK_LOGS        0x1003                      /**< The UUID of the Log info Characteristic. */


/*
	<!> Demo Lock 
*/

static uint8_t lock_operation[7];
static uint8_t lock_state[7];
static uint8_t lock_logs[20];

static struct {
	uint16_t                 service_handle;
	uint8_t                  uuid_type;

	ble_gatts_char_handles_t operation_handles;
	ble_gatts_char_handles_t state_handles;
	ble_gatts_char_handles_t log_handles;              
              
	uint16_t                 conn_handle;             /**< Handle of the current connection (as provided by the SoftDevice). BLE_CONN_HANDLE_INVALID if not in a connection. */
	bool                     is_notification_enabled; /**< Variable to indicate if the peer has enabled notification of the RX characteristic.*/
} lock_srv;

/**@brief Function for handling the @ref BLE_GAP_EVT_CONNECTED event from the S13X SoftDevice.
 *
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_connect(ble_evt_t * p_ble_evt)
{
    lock_srv.conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
}


/**@brief Function for handling the @ref BLE_GAP_EVT_DISCONNECTED event from the S13X SoftDevice.
 *
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_disconnect(ble_evt_t * p_ble_evt)
{
    UNUSED_PARAMETER(p_ble_evt);
    lock_srv.conn_handle = BLE_CONN_HANDLE_INVALID;
}


/**@brief Function for handling the @ref BLE_GATTS_EVT_WRITE event from the S13X SoftDevice.
 *
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_write(ble_evt_t * p_ble_evt)
{
    ble_gatts_evt_write_t * p_evt_write = &p_ble_evt->evt.gatts_evt.params.write;
	
    if ((p_evt_write->len == 2) &&
		((p_evt_write->handle == lock_srv.log_handles.cccd_handle) ||
	     (p_evt_write->handle == lock_srv.state_handles.cccd_handle)))
    {
        if (ble_srv_is_notification_enabled(p_evt_write->data))
        {
            lock_srv.is_notification_enabled = true;
        }
        else
        {
            lock_srv.is_notification_enabled = false;
        }
    }
    else
    {
        // Do Nothing. This event is not relevant for this service.
    }
}

/**@brief Function for handling the @ref BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST event from the S13X SoftDevice.
 *
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_auth_read(ble_evt_t * p_ble_evt)
{
	ble_gatts_evt_read_t * p_evt_r = &p_ble_evt->evt.gatts_evt.params.authorize_request.request.read;
	ble_gatts_rw_authorize_reply_params_t reply = {0};
	if (p_evt_r->handle == lock_srv.state_handles.value_handle)
	{
		if (get_mi_authorization() == UNAUTHORIZATION) {
			reply = (ble_gatts_rw_authorize_reply_params_t) {
				.type = BLE_GATTS_AUTHORIZE_TYPE_READ,
				.params.read.gatt_status = BLE_GATT_STATUS_ATTERR_READ_NOT_PERMITTED
			};
		} else {
			reply = (ble_gatts_rw_authorize_reply_params_t) {
				.type = BLE_GATTS_AUTHORIZE_TYPE_READ,
				.params.read.gatt_status = BLE_GATT_STATUS_SUCCESS,
				.params.read.p_data      = lock_state,
				.params.read.len         = sizeof(lock_state)
			};
		}
		uint32_t errno = sd_ble_gatts_rw_authorize_reply(lock_srv.conn_handle, &reply);
		APP_ERROR_CHECK(errno);
    }
    else if (p_evt_r->handle == lock_srv.log_handles.value_handle)
	{
		
    }
    else
    {
        // Do Nothing. This event is not relevant for this service.
    }
}

/**@brief Function for handling the @ref BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST event from the S13X SoftDevice.
 *
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_auth_write(ble_evt_t * p_ble_evt)
{
    ble_gatts_evt_write_t * p_evt_w = &p_ble_evt->evt.gatts_evt.params.authorize_request.request.write;
	ble_gatts_rw_authorize_reply_params_t reply = {0};
	if (p_evt_w->handle == lock_srv.operation_handles.value_handle)
    {
		if (get_mi_authorization() == UNAUTHORIZATION) {
			reply = (ble_gatts_rw_authorize_reply_params_t) {
				.type = BLE_GATTS_AUTHORIZE_TYPE_WRITE,
				.params.write.gatt_status = BLE_GATT_STATUS_ATTERR_WRITE_NOT_PERMITTED
			};
		} else {
			reply = (ble_gatts_rw_authorize_reply_params_t) {
				.type = BLE_GATTS_AUTHORIZE_TYPE_WRITE,
				.params.write.gatt_status = BLE_GATT_STATUS_SUCCESS,
				.params.write.update      = 1,
				.params.write.len         = p_evt_w->len,
				.params.write.p_data      = p_evt_w->data
			};
		}
		uint32_t errno = sd_ble_gatts_rw_authorize_reply(lock_srv.conn_handle, &reply);
		APP_ERROR_CHECK(errno);
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

	if (char_props.read) {
		BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.read_perm);
	}
	if (char_props.write || char_props.write_wo_resp) {
		BLE_GAP_CONN_SEC_MODE_SET_OPEN(&attr_md.write_perm);
	}

    attr_md.vloc       = p_char_value == NULL ? BLE_GATTS_VLOC_STACK : BLE_GATTS_VLOC_USER;
    attr_md.rd_auth    = 1;
    attr_md.wr_auth    = 1;
    attr_md.vlen       = 1;

	ble_uuid.type = lock_srv.uuid_type;
	ble_uuid.uuid = uuid;

    memset(&attr_char_value, 0, sizeof(attr_char_value));

    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.max_len   = char_len;
    attr_char_value.p_value   = p_char_value ? p_char_value : NULL;

    return sd_ble_gatts_characteristic_add(lock_srv.service_handle,
	                                       &char_md,
	                                       &attr_char_value,
	                                       p_handles);
}


void ble_lock_on_ble_evt(ble_evt_t * p_ble_evt)
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

		case BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST:
			if (p_ble_evt->evt.gatts_evt.params.authorize_request.type == BLE_GATTS_AUTHORIZE_TYPE_READ)
				on_auth_read(p_ble_evt);
			else if (p_ble_evt->evt.gatts_evt.params.authorize_request.type == BLE_GATTS_AUTHORIZE_TYPE_WRITE)
				on_auth_write(p_ble_evt);
			break;		

		case BLE_GATTS_EVT_HVC:
			break;

		case BLE_GATTS_EVT_TIMEOUT:
			break;

        default:
            // No implementation needed.
            break;
    }
}

uint32_t ble_lock_init()
{
	uint32_t      err_code;
	ble_uuid_t    ble_uuid;
	ble_uuid128_t lock_srv_base_uuid = {0};
	memcpy(lock_srv_base_uuid.uuid128, "mi.miot.ble", 12);

//    VERIFY_PARAM_NOT_NULL(p_mi_s_init);

	// Initialize the service structure.
	lock_srv.conn_handle             = BLE_CONN_HANDLE_INVALID;
	lock_srv.is_notification_enabled = false;

	/**@snippet [Adding proprietary Service to S13x SoftDevice] */
	// Add a MI Lock UUID.
	err_code = sd_ble_uuid_vs_add(&lock_srv_base_uuid, &lock_srv.uuid_type);
	VERIFY_SUCCESS(err_code);

	ble_uuid.type = lock_srv.uuid_type;
	ble_uuid.uuid = BLE_UUID_LOCK_SERVICE;

	// Add the service.
	err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY,
	                                    &ble_uuid,
	                                    &lock_srv.service_handle);
	APP_ERROR_CHECK(err_code);

	// Add the Lock operation Characteristic.
	ble_gatt_char_props_t char_props = {0};
	char_props.write                 = 1;
	err_code = char_add(BLE_UUID_LOCK_OPERATION, lock_operation, sizeof(lock_operation),
	                    char_props, &lock_srv.operation_handles);
	APP_ERROR_CHECK(err_code);

    // Add the Lock state Characteristic.
	char_props = (ble_gatt_char_props_t){0};
	char_props.read                  = 1;
	char_props.notify                = 1;
	err_code = char_add(BLE_UUID_LOCK_STATE, lock_state, sizeof(lock_state),
	                    char_props, &lock_srv.state_handles);
	APP_ERROR_CHECK(err_code);

    // Add the Lock state Characteristic.
	char_props = (ble_gatt_char_props_t){0};
	char_props.read                  = 1;
	char_props.notify                = 1;
	err_code = char_add(BLE_UUID_LOCK_STATE, lock_state, sizeof(lock_state),
	                    char_props, &lock_srv.state_handles);
	APP_ERROR_CHECK(err_code);

    // Add the Lock logs Characteristic.
	char_props = (ble_gatt_char_props_t){0};
	char_props.read                  = 1;
	char_props.notify                = 1;
	err_code = char_add(BLE_UUID_LOCK_STATE, lock_state, sizeof(lock_state),
	                    char_props, &lock_srv.state_handles);
	APP_ERROR_CHECK(err_code);

	return NRF_SUCCESS;
}

uint8_t get_lock_opcode(uint8_t *p_opcode)
{
	if (lock_srv.conn_handle == BLE_CONN_HANDLE_INVALID)
		return 1;

	uint8_t data[7] = {0};

	if(memcmp(data, lock_operation, sizeof(data)) == 0)
		return 2;

	uint8_t errno = mi_session_decrypt(lock_operation, 7, data);

	if (errno != 0) {
		NRF_LOG_INFO("Opcode decrypt %d\n", errno);
		return 3;
	}

	*p_opcode = *data;

	memset(lock_operation, 0, sizeof(lock_operation));

	return 0;
}

uint32_t send_lock_stat(uint8_t status)
{
    ble_gatts_hvx_params_t hvx_params = {0};
	uint32_t errno;
	uint8_t  value[7] = {0};
	uint16_t length   = sizeof(value);

    if ((lock_srv.conn_handle == BLE_CONN_HANDLE_INVALID) || (!lock_srv.is_notification_enabled))
    {
        return NRF_ERROR_INVALID_STATE;
    }
	
	mi_session_encrypt(&status, sizeof(status), value);

    hvx_params.handle = lock_srv.state_handles.value_handle;
    hvx_params.p_data = value;
    hvx_params.p_len  = &length;
    hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;

    errno = sd_ble_gatts_hvx(lock_srv.conn_handle, &hvx_params);

	if (errno != NRF_SUCCESS) {
		NRF_LOG_INFO("Cann't send lock stat : %d\n", errno);
	}

	return errno;
}

