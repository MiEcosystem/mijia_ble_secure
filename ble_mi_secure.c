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
#include "ble_mi_secure.h"
#include "mi_secure.h"
#include "mi_crypto.h"
#include "mi_config.h"

#define NRF_LOG_MODULE_NAME "BLEM"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) < (b) ? (b) : (a))

#define BLE_UUID_MI_VERS   0x0004                      /**< The UUID of the Version Characteristic. */
#define BLE_UUID_MI_CTRLP  0x0010                      /**< The UUID of the Control Point Characteristic. */
#define BLE_UUID_MI_FXFER  0x0015                      /**< The UUID of the Fast xfer Characteristic. */
#define BLE_UUID_MI_SECURE 0x0016                      /**< The UUID of the Secure Characteristic. */

#define PUBKEY_BYTE 255
#define FRAME_CTRL  0

static void opcode_parse(uint8_t *pdata, uint8_t len);
static void fast_xfer_rxd(fast_xfer_t *pxfer, uint8_t *pdata, uint8_t len);
static void rxfer_rx_decode(reliable_xfer_t *pxfer, uint8_t *pdata, uint8_t len);

static ble_mi_t mi_srv;
static uint32_t auth_value;
static uint8_t version[20] = BLE_SDK_AND_USER_VERSION;
fast_xfer_t fast_control_block = {.type = PUBKEY};
reliable_xfer_t rxfer_control_block;

/**@brief Function for handling the @ref BLE_GAP_EVT_CONNECTED event from the S13X SoftDevice.
 *
 * @param[in] p_mi_s    Xiaomi Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_connect(ble_evt_t * p_ble_evt)
{
	uint32_t errno;
    mi_srv.conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
	ble_gap_conn_params_t conn_param = p_ble_evt->evt.gap_evt.params.connected.conn_params;
	ble_gap_conn_params_t pref_conn_param = {
		.min_conn_interval = MSEC_TO_UNITS(10, UNIT_1_25_MS),
		.max_conn_interval = MSEC_TO_UNITS(20, UNIT_1_25_MS),
		.slave_latency     = 0,
		.conn_sup_timeout  = MSEC_TO_UNITS(4000, UNIT_10_MS)
	};

	sd_ble_gap_conn_param_update(mi_srv.conn_handle, &pref_conn_param);

	errno = sd_ble_gatts_sys_attr_set(mi_srv.conn_handle, NULL, 0, 0);
	APP_ERROR_CHECK(errno);

	ble_gap_adv_params_t adv_params;
	memset(&adv_params, 0, sizeof(adv_params));
	
	adv_params.type        = BLE_GAP_ADV_TYPE_ADV_SCAN_IND;
	adv_params.fp          = BLE_GAP_ADV_FP_ANY;
	adv_params.interval    = MSEC_TO_UNITS(100, UNIT_0_625_MS); // must >= 100 ms
	adv_params.timeout     = 0;

	errno = sd_ble_gap_adv_start(&adv_params);
	APP_ERROR_CHECK(errno);

	NRF_LOG_RAW_INFO(NRF_LOG_COLOR_CODE_CYAN"Connected Peer MAC: ");
	NRF_LOG_RAW_HEXDUMP_INFO(p_ble_evt->evt.gap_evt.params.connected.peer_addr.addr, BLE_GAP_ADDR_LEN);
	NRF_LOG_RAW_INFO(NRF_LOG_COLOR_CODE_CYAN"Conn param default: min %2d, max %2d\n",
	                 conn_param.min_conn_interval, conn_param.min_conn_interval);
}

/**@brief Function for handling the @ref BLE_GAP_EVT_DISCONNECTED event from the S13X SoftDevice.
 *
 * @param[in] p_mi_s    Xiaomi Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_disconnect(ble_evt_t * p_ble_evt)
{
    mi_srv.conn_handle = BLE_CONN_HANDLE_INVALID;

	set_mi_authorization(UNAUTHORIZATION);
	mi_crypto_uninit();

	NRF_LOG_RAW_INFO(NRF_LOG_COLOR_CODE_CYAN"Disconnect reason %X.\n",
	                 p_ble_evt->evt.gap_evt.params.disconnected.reason);

	// Stop scannable adv
	uint32_t errno = sd_ble_gap_adv_stop();
	APP_ERROR_CHECK(errno);
}

/**@brief Function for handling the @ref BLE_GAP_EVT_CONN_PARAM_UPDATE event from the S13X SoftDevice.
 *
 * @param[in] p_mi_s    Xiaomi Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_conn_params_update(ble_evt_t * p_ble_evt)
{
	ble_gap_conn_params_t conn_param = 
		p_ble_evt->evt.gap_evt.params.conn_param_update.conn_params;

	NRF_LOG_RAW_INFO(NRF_LOG_COLOR_CODE_BLUE"Conn param update : min %d, max %d\n",
			         conn_param.min_conn_interval, conn_param.min_conn_interval);
}


/**@brief Function for handling the @ref BLE_GATTS_EVT_WRITE event from the S13X SoftDevice.
 *
 * @param[in] p_mi_s    Xiaomi Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_write(ble_evt_t * p_ble_evt)
{
    ble_gatts_evt_write_t * p_evt_write = &p_ble_evt->evt.gatts_evt.params.write;
	uint16_t   len = p_evt_write->len;
	uint8_t *pdata = p_evt_write->data;
    if (len == 2
		&& (p_evt_write->handle == mi_srv.ctrl_point_handles.cccd_handle
			|| p_evt_write->handle == mi_srv.fast_xfer_handles.cccd_handle
			|| p_evt_write->handle == mi_srv.secure_handles.cccd_handle)) 
	{
        if (ble_srv_is_notification_enabled(pdata))
            mi_srv.is_notification_enabled = true;
        else
            mi_srv.is_notification_enabled = false;
    }
    else if (p_evt_write->handle == mi_srv.ctrl_point_handles.value_handle)
    {
        opcode_parse(pdata, len);
    }
    else if (p_evt_write->handle == mi_srv.secure_handles.value_handle)
    {
		NRF_LOG_RAW_HEXDUMP_INFO(pdata, len > 16 ? 16 : len);

		reliable_xfer_frame_t *pframe = (void*)pdata;
		uint16_t  curr_sn = pframe->sn;
		
		if (curr_sn == FRAME_CTRL ) {
			if (rxfer_control_block.state == RXFER_WAIT_CMD &&
			    pframe->ctrl.mode == MODE_CMD) 
			{
				fctrl_cmd_t cmd = (fctrl_cmd_t)pframe->ctrl.type;
				rxfer_control_block.mode = MODE_CMD;
				rxfer_control_block.cmd = cmd;
				switch (cmd) {
					case DEV_PUBKEY:
					case DEV_LOGIN_INFO:
					case DEV_SHARE_INFO:
						rxfer_control_block.rx_num = *(uint16_t*)pframe->ctrl.arg;
						break;
					default:
						NRF_LOG_ERROR("Unknow rxfer CMD.\n");
				}
			}
			else if (rxfer_control_block.state == RXFER_WAIT_ACK &&
			         pframe->ctrl.mode == MODE_ACK)
			{
				fctrl_ack_t ack = (fctrl_ack_t)pframe->ctrl.type;
				rxfer_control_block.mode = MODE_ACK;
				rxfer_control_block.ack = ack;
				switch (ack) {
					case A_SUCCESS:
						rxfer_control_block.curr_sn = 0;

						rxfer_control_block.state = RXFER_WAIT_CMD;

						break;
					case A_READY:
						rxfer_control_block.curr_sn = 0;
						rxfer_control_block.state = RXFER_TXD;
						break;
					case A_LOST:
						rxfer_control_block.curr_sn = *(uint16_t*)pframe->ctrl.arg;
						break;
					default:
						NRF_LOG_ERROR("Unknow rxfer ACK.\n");
				}
			}
			else {
				NRF_LOG_ERROR("recv malformed packet !\n");
				// malware 
				// TODO: handle this exception...
			}
		}
		else if (rxfer_control_block.state == RXFER_RXD)
		{
			rxfer_control_block.curr_sn = curr_sn;
			if (curr_sn < rxfer_control_block.rx_num && len == 20)
			{
				rxfer_rx_decode(&rxfer_control_block, pdata, 20);
			}
			else if (curr_sn == rxfer_control_block.rx_num)
			{
				if (rxfer_control_block.rx_num == rxfer_control_block.max_rx_num)
					rxfer_rx_decode(&rxfer_control_block, pdata, 
				                      MIN(len, rxfer_control_block.last_bytes+2));
				else
					rxfer_rx_decode(&rxfer_control_block, pdata, len);
			}
			else
			{
				NRF_LOG_ERROR("recv illegal rxfer data. SN:%d %d\n", curr_sn, len);
				rxfer_control_block.curr_sn = 0;
				// TODO: handle this exception...
			}
		}
    }
    else if (p_evt_write->handle == mi_srv.fast_xfer_handles.value_handle)
    {
		fast_xfer_frame_t *pframe = (void*)pdata;
        if (pframe->type == PUBKEY && pframe->remain_len < PUBKEY_BYTE)
			fast_xfer_rxd(&fast_control_block, pdata, len);
		else
			NRF_LOG_ERROR("Unknow fast xfer data type\n");
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
    attr_md.rd_auth    = 0;
    attr_md.wr_auth    = 0;
    attr_md.vlen       = 1;

    BLE_UUID_BLE_ASSIGN(ble_uuid, uuid);

    memset(&attr_char_value, 0, sizeof(attr_char_value));

    attr_char_value.p_uuid    = &ble_uuid;
    attr_char_value.p_attr_md = &attr_md;
    attr_char_value.max_len   = char_len;
	attr_char_value.init_len  = p_char_value ? char_len : 0;
    attr_char_value.p_value   = p_char_value ? p_char_value : NULL;

    return sd_ble_gatts_characteristic_add(mi_srv.service_handle,
	                                       &char_md,
	                                       &attr_char_value,
	                                       p_handles);
}

static void opcode_parse(uint8_t *pdata, uint8_t len)
{
	memcpy(&auth_value, pdata, len);
	
	switch (auth_value) {
	case REG_START:
	case LOG_START:
	case SHARED_LOG_START:
	case SHARED_LOG_START_W_CERT:
		mi_scheduler_start(auth_value);
		break;

	default:
		NRF_LOG_WARNING("NON-START OPCODE %X\n", auth_value);
		break;
	}

	return;
}

void fast_xfer_rxd(fast_xfer_t *pxfer, uint8_t *pdata, uint8_t len)
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

	uint8_t *addr = pxfer->data + sizeof(pxfer->data) - curr_len;
	memcpy(addr, pframe->data, data_len);

	pxfer->curr_len += data_len;
	
	if (pxfer->curr_len == pxfer->full_len ) {
		pxfer->avail = 1;
		pxfer->curr_len = 0;
	}
}

int fast_xfer_recive(fast_xfer_t *pxfer)
{
	if (!pxfer->avail) {
		return 1;
	}
	else {
		return 0;
	}
}

static int fast_xfer_txd(fast_xfer_t *pxfer)
{
	ble_gatts_hvx_params_t hvx_params;
	fast_xfer_tx_frame_t        frame;
	uint32_t                 data_len;
	uint32_t                    errno;

    memset(&hvx_params, 0, sizeof(hvx_params));
	memset(&frame,      0, sizeof(frame));

	data_len = pxfer->curr_len > 18 ? 18 : pxfer->curr_len;

	frame.remain_len = pxfer->curr_len;
	frame.type       = pxfer->type;
	memcpy(frame.data,
	       pxfer->data + pxfer->full_len - pxfer->curr_len,
	       data_len);
	
	data_len += 2;      // add 2 bytes (remain_len and type)
    hvx_params.handle = mi_srv.fast_xfer_handles.value_handle;
    hvx_params.p_data = (void*)&frame;
    hvx_params.p_len  = (uint16_t*)&data_len;
    hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;

    errno = sd_ble_gatts_hvx(mi_srv.conn_handle, &hvx_params);

	if (errno == NRF_SUCCESS) {
		pxfer->curr_len -= data_len - 2;
		NRF_LOG_INFO("Send %d bytes\n", data_len-2);
	}

	return errno;
}

int fast_xfer_send(fast_xfer_t *pxfer)
{
	uint32_t errno;
	if ((mi_srv.conn_handle == BLE_CONN_HANDLE_INVALID) || (!mi_srv.is_notification_enabled))
    {
        return NRF_ERROR_INVALID_STATE;
    }
	
	uint8_t free_packet_cnt;
	sd_ble_tx_packet_count_get(mi_srv.conn_handle, &free_packet_cnt);
	NRF_LOG_INFO("free TX packets: %d\n", free_packet_cnt);
	while( free_packet_cnt-- ) {
		errno = fast_xfer_txd(pxfer);
		if (errno != NRF_SUCCESS) {
			NRF_LOG_ERROR("Notify errno %d", errno);
			break;
		}
		else if (pxfer->curr_len == 0 ) {
			NRF_LOG_INFO("TX completed.\n");
			return 0;
		}
	}
	return 1;
}

static void rxfer_rx_decode(reliable_xfer_t *pxfer, uint8_t *pdata, uint8_t len)
{
	reliable_xfer_frame_t      *pframe = (void*)pdata;
	int8_t                    data_len = len - sizeof(pframe->sn);

	if (data_len > 0)
		memcpy(pxfer->pdata + (pframe->sn - 1) * 18, pframe->data, data_len);
	else
		NRF_LOG_ERROR("rxd data len error. \n");
}

int reliable_xfer_cmd(fctrl_cmd_t cmd, ...)
{
	ble_gatts_hvx_params_t hvx_params = {0};
	reliable_xfer_frame_t       frame = {0};
	uint16_t                 data_len;
	uint32_t                    errno;
	uint16_t                      arg;

	frame.ctrl.mode = MODE_CMD;
	frame.ctrl.type =      cmd;

	va_list ap;
	va_start(ap, cmd);
	arg = va_arg(ap, int);
	if ( arg != 0 ) {
		*(uint16_t*)frame.ctrl.arg = arg;
	}
	va_end(ap);

	data_len = sizeof(frame.sn) + sizeof(frame.ctrl);
    hvx_params.handle = mi_srv.secure_handles.value_handle;
    hvx_params.p_data = (void*)&frame;
    hvx_params.p_len  = &data_len;
    hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;

	// TODO : exception handler
	if (mi_srv.conn_handle == BLE_CONN_HANDLE_INVALID)
		NRF_LOG_ERROR("Exception disconnect in BLE.\n");

    errno = sd_ble_gatts_hvx(mi_srv.conn_handle, &hvx_params);

	if (errno != NRF_SUCCESS) {
		NRF_LOG_INFO("Cann't send CMD %X : %d\n", cmd, errno);
	} else {
		NRF_LOG_INFO("CMD ");
		NRF_LOG_RAW_HEXDUMP_INFO(hvx_params.p_data, *hvx_params.p_len);
	}

	return errno;
}

int reliable_xfer_data(reliable_xfer_t *pxfer, uint16_t sn)
{
	ble_gatts_hvx_params_t hvx_params = {0};
	reliable_xfer_frame_t       frame = {0};
	uint16_t                 data_len;
	uint32_t                    errno;

	uint8_t      (*pdata)[18] = (void*)pxfer->pdata;

	frame.sn = sn;
	pdata   += sn - 1;

	if (sn == pxfer->tx_num) {
		data_len = pxfer->last_bytes;
	}
	else {
		data_len = sizeof(frame.data);
	}
	
	memcpy(frame.data, pdata, data_len);
	
	data_len += sizeof(frame.sn);
    hvx_params.handle = mi_srv.secure_handles.value_handle;
    hvx_params.p_data = (void*)&frame;
    hvx_params.p_len  = &data_len;
    hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;

    errno = sd_ble_gatts_hvx(mi_srv.conn_handle, &hvx_params);
	
	if (errno != NRF_SUCCESS) {
//		NRF_LOG_RAW_INFO("Cann't send pkt %d: %X\n", sn, errno);
	}

	return errno;
}

int reliable_xfer_ack(fctrl_ack_t ack, ...)
{
	ble_gatts_hvx_params_t hvx_params = {0};
	reliable_xfer_frame_t       frame = {0};
	uint16_t                 data_len;
	uint32_t                    errno;
	
	frame.ctrl.mode = MODE_ACK;
	frame.ctrl.type =      ack;
	data_len = sizeof(frame.sn) + sizeof(frame.ctrl.type) + sizeof(frame.ctrl.mode);

	if (ack == A_LOST) {
		va_list ap;
		va_start(ap, ack);
		uint16_t arg = va_arg(ap, int);
		if ( arg != 0 ) {
			*(uint16_t*)frame.ctrl.arg = arg;
			data_len += sizeof(frame.ctrl.arg);
		}
		va_end(ap);
	}
	
    hvx_params.handle = mi_srv.secure_handles.value_handle;
    hvx_params.p_data = (void*)&frame;
    hvx_params.p_len  = &data_len;
    hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;
	
	// TODO : exception handler
	if (mi_srv.conn_handle == BLE_CONN_HANDLE_INVALID) {
		NRF_LOG_ERROR("Exception disconnect in BLE.\n");
		return 0;
	}
    errno = sd_ble_gatts_hvx(mi_srv.conn_handle, &hvx_params);
	
	if (errno != NRF_SUCCESS) {
		NRF_LOG_INFO("Cann't send ACK %x: %X\n", ack, errno);
		// TODO : catch the exception.
	} else {
		NRF_LOG_INFO("ACK ");
		NRF_LOG_RAW_HEXDUMP_INFO(hvx_params.p_data, *hvx_params.p_len);
	}

	return errno;
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

        case BLE_GAP_EVT_CONN_PARAM_UPDATE:
			on_conn_params_update(p_ble_evt);
            break;

        case BLE_GATTS_EVT_WRITE:
            on_write(p_ble_evt);
            break;

		case BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST:
			break;		

		case BLE_GATTS_EVT_HVC:
			break;

		case BLE_GATTS_EVT_TIMEOUT:
			break;

        default:
            break;
    }
}

uint32_t ble_mi_init(const ble_mi_init_t * p_mi_s_init)
{
    uint32_t      err_code;
    ble_uuid_t    ble_uuid;

    VERIFY_PARAM_NOT_NULL(p_mi_s_init);

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
    APP_ERROR_CHECK(err_code);

    // Add the Version Characteristic.
	ble_gatt_char_props_t char_props = {0};
	char_props.read                  = 1;
	err_code = char_add(BLE_UUID_MI_VERS, version, sizeof(version),
	                    char_props, &mi_srv.version_handles);
	APP_ERROR_CHECK(err_code);

    // Add the Control Point Characteristic.
	char_props = (ble_gatt_char_props_t){0};
	char_props.write_wo_resp         = 1;
	char_props.notify                = 1;
	err_code = char_add(BLE_UUID_MI_CTRLP, NULL, 4, char_props, &mi_srv.ctrl_point_handles);
	APP_ERROR_CHECK(err_code);

    // Add the Secure AUTH Characteristic.
	char_props = (ble_gatt_char_props_t){0};
	char_props.write_wo_resp         = 1;
	char_props.notify                = 1;
	err_code = char_add(BLE_UUID_MI_SECURE, NULL, 20, char_props, &mi_srv.secure_handles);
	APP_ERROR_CHECK(err_code);

//	// Add the Fast xfer Characteristic.
//	char_props = (ble_gatt_char_props_t){0};
//	char_props.write_wo_resp         = 1;
//	char_props.notify                = 1;
//	err_code = char_add(BLE_UUID_MI_FXFER, NULL, 20, char_props, &mi_srv.fast_xfer_handles);
//	VERIFY_SUCCESS(err_code);
	
	return NRF_SUCCESS;
}

uint32_t auth_send(uint32_t status)
{
    ble_gatts_hvx_params_t hvx_params = {0};
	uint32_t errno;
	uint16_t length = 4;

    if ((mi_srv.conn_handle == BLE_CONN_HANDLE_INVALID) || (!mi_srv.is_notification_enabled))
    {
        return NRF_ERROR_INVALID_STATE;
    }

    if (length > BLE_MI_MAX_DATA_LEN)
    {
        return NRF_ERROR_INVALID_PARAM;
    }

    hvx_params.handle = mi_srv.ctrl_point_handles.value_handle;
    hvx_params.p_data = (uint8_t*)&status;
    hvx_params.p_len  = &length;
    hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;

    errno = sd_ble_gatts_hvx(mi_srv.conn_handle, &hvx_params);

	if (errno != NRF_SUCCESS) {
		NRF_LOG_INFO("Cann't send auth : %X\n", errno);
	}

	return errno;
}

uint32_t auth_recv(void)
{
	return auth_value;
}
