/* Copyright (c) 2014 Nordic Semiconductor. All Rights Reserved.
 *
 * The information contained herein is property of Nordic Semiconductor ASA.
 * Terms and conditions of usage are described in detail in NORDIC
 * SEMICONDUCTOR STANDARD SOFTWARE LICENSE AGREEMENT.
 *
 * Licensees are granted free, non-transferable use of the information. NO
 * WARRANTY of ANY KIND is provided. This heading must NOT be removed from
 * the file.
 *
 */

/** @file
 *
 * @defgroup ble_sdk_uart_over_ble_main main.c
 * @{
 * @ingroup  ble_sdk_app_nus_eval
 * @brief    UART over BLE application main file.
 *
 * This file contains the source code for a sample application that uses the Nordic UART service.
 * This application uses the @ref srvlib_conn_params module.
 */
//
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "nordic_common.h"
#include "nrf.h"
#include "ble_hci.h"
#include "ble_advdata.h"
#include "ble_advertising.h"
#include "ble_conn_params.h"
#include "softdevice_handler.h"
#include "app_timer.h"
#include "app_button.h"
#include "fstorage.h"
#include "fds.h"
#include "ble_nus.h"

#define NRF_LOG_MODULE_NAME "MAIN"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"

#include "ble_mi_secure.h"
#include "mi_secure.h"
#include "mi_beacon.h"
#include "mi_crypto.h"
#include "mi_psm.h"

#include "app_util_platform.h"
#include "bsp.h"
#include "bsp_btn_ble.h"
#include "nrf_drv_twi_patched.h"

#include "ble_lock.h"

#if 1
#define APP_PRODUCT_ID                  0x01CF            // Xiaomi Secure BLE dev board
#else
#define APP_PRODUCT_ID                  0x009C            // Xiaomi BLE dev board
#endif

#define RTT_CTRL_CLEAR                  "[2J"

#define IS_SRVC_CHANGED_CHARACT_PRESENT 0                                           /**< Include the service_changed characteristic. If not enabled, the server's database cannot be changed for the lifetime of the device. */

#if (NRF_SD_BLE_API_VERSION == 3)
#define NRF_BLE_MAX_MTU_SIZE            GATT_MTU_SIZE_DEFAULT                       /**< MTU size used in the softdevice enabling and to reply to a BLE_GATTS_EVT_EXCHANGE_MTU_REQUEST event. */
#endif

#define APP_FEATURE_NOT_SUPPORTED       BLE_GATT_STATUS_ATTERR_APP_BEGIN + 2        /**< Reply when unsupported features are requested. */

#define CENTRAL_LINK_COUNT              0                                           /**< Number of central links used by the application. When changing this number remember to adjust the RAM settings*/
#define PERIPHERAL_LINK_COUNT           1                                           /**< Number of peripheral links used by the application. When changing this number remember to adjust the RAM settings*/

#ifdef NRF52
#define DEVICE_NAME                     "Secure_nRF52"                              /**< Name of device. Will be included in the advertising data. */
#else
#define DEVICE_NAME                     "Secure_nRF51"                              /**< Name of device. Will be included in the advertising data. */
#endif

#define APP_ADV_INTERVAL                MSEC_TO_UNITS(200, UNIT_0_625_MS)           /**< The advertising interval (in units of 0.625 ms. This value corresponds to 40 ms). */
#define APP_ADV_TIMEOUT_IN_SECONDS      0                                           /**< The advertising timeout (in units of seconds). */

#define APP_TIMER_PRESCALER             0                                           /**< Value of the RTC1 PRESCALER register. */
#define APP_TIMER_OP_QUEUE_SIZE         8                                           /**< Size of timer operation queues. */

#define MIN_CONN_INTERVAL               MSEC_TO_UNITS(100, UNIT_1_25_MS)             /**< Minimum acceptable connection interval (10 ms), Connection interval uses 1.25 ms units. */
#define MAX_CONN_INTERVAL               MSEC_TO_UNITS(200, UNIT_1_25_MS)             /**< Maximum acceptable connection interval (40 ms), Connection interval uses 1.25 ms units. */
#define SLAVE_LATENCY                   0                                           /**< Slave latency. */
#define CONN_SUP_TIMEOUT                MSEC_TO_UNITS(4000, UNIT_10_MS)             /**< Connection supervisory timeout (4 seconds), Supervision Timeout uses 10 ms units. */
#define FIRST_CONN_PARAMS_UPDATE_DELAY  APP_TIMER_TICKS(5000, APP_TIMER_PRESCALER)  /**< Time from initiating event (connect or start of notification) to first time sd_ble_gap_conn_param_update is called (5 seconds). */
#define NEXT_CONN_PARAMS_UPDATE_DELAY   APP_TIMER_TICKS(30000, APP_TIMER_PRESCALER) /**< Time between each call to sd_ble_gap_conn_param_update after the first call (30 seconds). */
#define MAX_CONN_PARAMS_UPDATE_COUNT    3                                           /**< Number of attempts before giving up the connection parameter negotiation. */

#define DEAD_BEEF                       0xDEADBEEF                                  /**< Value used as error code on stack dump, can be used to identify stack location on stack unwind. */

APP_TIMER_DEF(poll_timer);

static ble_nus_t                        m_nus;                                      /**< Structure to identify the Nordic UART Service. */
static uint16_t                         m_conn_handle = BLE_CONN_HANDLE_INVALID;    /**< Handle of the current connection. */

static ble_uuid_t                       m_adv_uuids[] = {{BLE_UUID_MI_SERVICE, BLE_UUID_TYPE_BLE}};  /**< Universally unique service identifier. */

/* Indicates if operation on TWI has ended. */
volatile bool m_twi0_xfer_done = false;

/* TWI instance. */
const nrf_drv_twi_t TWI0 = NRF_DRV_TWI_INSTANCE(0);

/**@brief Function for assert macro callback.
 *
 * @details This function will be called in case of an assert in the SoftDevice.
 *
 * @warning This handler is an example only and does not fit a final product. You need to analyse
 *          how your product is supposed to react in case of Assert.
 * @warning On assert from the SoftDevice, the system can only recover on reset.
 *
 * @param[in] line_num    Line number of the failing ASSERT call.
 * @param[in] p_file_name File name of the failing ASSERT call.
 */
void assert_nrf_callback(uint16_t line_num, const uint8_t * p_file_name)
{
    app_error_handler(DEAD_BEEF, line_num, p_file_name);
}


/**@brief Function for the GAP initialization.
 *
 * @details This function will set up all the necessary GAP (Generic Access Profile) parameters of
 *          the device. It also sets the permissions and appearance.
 */
static void gap_params_init(void)
{
    uint32_t                err_code;
    ble_gap_conn_params_t   gap_conn_params;
    ble_gap_conn_sec_mode_t sec_mode;

    BLE_GAP_CONN_SEC_MODE_SET_NO_ACCESS(&sec_mode);

    err_code = sd_ble_gap_device_name_set(&sec_mode,
                                          (const uint8_t *) DEVICE_NAME,
                                          strlen(DEVICE_NAME));
    APP_ERROR_CHECK(err_code);

    memset(&gap_conn_params, 0, sizeof(gap_conn_params));

    gap_conn_params.min_conn_interval = MIN_CONN_INTERVAL;
    gap_conn_params.max_conn_interval = MAX_CONN_INTERVAL;
    gap_conn_params.slave_latency     = SLAVE_LATENCY;
    gap_conn_params.conn_sup_timeout  = CONN_SUP_TIMEOUT;

    err_code = sd_ble_gap_ppcp_set(&gap_conn_params);
    APP_ERROR_CHECK(err_code);
}

/**@brief Function for handling the data from the Nordic UART Service.
 *
 * @details This function will process the data received from the Nordic UART BLE Service and send
 *          it to the UART module.
 *
 * @param[in] p_nus    Nordic UART Service structure.
 * @param[in] p_data   Data to be send to UART module.
 * @param[in] length   Length of the data.
 */
/**@snippet [Handling the data received over BLE] */
uint8_t msg[32];
static void nus_data_handler(ble_nus_t * p_nus, uint8_t * p_data, uint16_t length)
{
	uint32_t errno;

	NRF_LOG_HEXDUMP_INFO(p_data, length);
	errno = mi_session_decrypt(p_data, length, msg);

	if (errno != NRF_SUCCESS) {
		length = 1;
		msg[0] = 0xFF;
	} else {
		NRF_LOG_HEXDUMP_INFO(msg, length-6);
		mi_session_encrypt(msg, length-6, msg);
		NRF_LOG_HEXDUMP_INFO(msg, length);
	}
	
	ble_nus_string_send(&m_nus, msg, length);

}


/**@brief Function for initializing services that will be used by the application.
 */
static void services_init(void)
{
    uint32_t       err_code;
    ble_nus_init_t nus_init;
	ble_mi_init_t  mi_init;

    memset(&nus_init, 0, sizeof(nus_init));

    nus_init.data_handler = nus_data_handler;

    err_code = ble_nus_init(&m_nus, &nus_init);
    APP_ERROR_CHECK(err_code);
	
	memset(&mi_init, 0, sizeof(mi_init));
	
	mi_init.data_handler = NULL;

	err_code = ble_mi_init(&mi_init);
	APP_ERROR_CHECK(err_code);

	ble_lock_init();
}


/**@brief Function for handling an event from the Connection Parameters Module.
 *
 * @details This function will be called for all events in the Connection Parameters Module
 *          which are passed to the application.
 *
 * @note All this function does is to disconnect. This could have been done by simply setting
 *       the disconnect_on_fail config parameter, but instead we use the event handler
 *       mechanism to demonstrate its use.
 *
 * @param[in] p_evt  Event received from the Connection Parameters Module.
 */
static void on_conn_params_evt(ble_conn_params_evt_t * p_evt)
{
    uint32_t err_code;

    if (p_evt->evt_type == BLE_CONN_PARAMS_EVT_FAILED)
    {
        err_code = sd_ble_gap_disconnect(m_conn_handle, BLE_HCI_CONN_INTERVAL_UNACCEPTABLE);
        APP_ERROR_CHECK(err_code);
    }
}


/**@brief Function for handling errors from the Connection Parameters module.
 *
 * @param[in] nrf_error  Error code containing information about what went wrong.
 */
static void conn_params_error_handler(uint32_t nrf_error)
{
//    APP_ERROR_HANDLER(nrf_error);
	NRF_LOG_ERROR("conn param error %X\n", nrf_error);
}


/**@brief Function for initializing the Connection Parameters module.
 */
static void conn_params_init(void)
{
    uint32_t               err_code;
    ble_conn_params_init_t cp_init;

    memset(&cp_init, 0, sizeof(cp_init));

    cp_init.p_conn_params                  = NULL;
    cp_init.first_conn_params_update_delay = FIRST_CONN_PARAMS_UPDATE_DELAY;
    cp_init.next_conn_params_update_delay  = NEXT_CONN_PARAMS_UPDATE_DELAY;
    cp_init.max_conn_params_update_count   = MAX_CONN_PARAMS_UPDATE_COUNT;
    cp_init.start_on_notify_cccd_handle    = BLE_GATT_HANDLE_INVALID;
    cp_init.disconnect_on_fail             = false;
    cp_init.evt_handler                    = on_conn_params_evt;
    cp_init.error_handler                  = conn_params_error_handler;

    err_code = ble_conn_params_init(&cp_init);
    APP_ERROR_CHECK(err_code);
}


/**@brief Function for putting the chip into sleep mode.
 *
 * @note This function will not return.
 */
static void sleep_mode_enter(void)
{
    uint32_t err_code = bsp_indication_set(BSP_INDICATE_IDLE);
    APP_ERROR_CHECK(err_code);

    // Prepare wakeup buttons.
    err_code = bsp_btn_ble_sleep_mode_prepare();
    APP_ERROR_CHECK(err_code);

    // Go to system-off mode (this function will not return; wakeup will cause a reset).
    err_code = sd_power_system_off();
    APP_ERROR_CHECK(err_code);
}

static void advertising_init(void);
/**@brief Function for handling advertising events.
 *
 * @details This function will be called for advertising events which are passed to the application.
 *
 * @param[in] ble_adv_evt  Advertising event.
 */
static void on_adv_evt(ble_adv_evt_t ble_adv_evt)
{
    uint32_t err_code;
    switch (ble_adv_evt)
    {
        case BLE_ADV_EVT_FAST:
			advertising_init();
            err_code = bsp_indication_set(BSP_INDICATE_ADVERTISING);
            APP_ERROR_CHECK(err_code);
            break;
        case BLE_ADV_EVT_IDLE:
            break;
        default:
            break;
    }
}


/**@brief Function for the application's SoftDevice event handler.
 *
 * @param[in] p_ble_evt SoftDevice event.
 */
static void on_ble_evt(ble_evt_t * p_ble_evt)
{
    uint32_t err_code;

    switch (p_ble_evt->header.evt_id)
    {
        case BLE_GAP_EVT_CONNECTED:
            err_code = bsp_indication_set(BSP_INDICATE_CONNECTED);
            APP_ERROR_CHECK(err_code);
            m_conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
            break; // BLE_GAP_EVT_CONNECTED

        case BLE_GAP_EVT_DISCONNECTED:
            err_code = bsp_indication_set(BSP_INDICATE_IDLE);
            APP_ERROR_CHECK(err_code);
            m_conn_handle = BLE_CONN_HANDLE_INVALID;
            break; // BLE_GAP_EVT_DISCONNECTED

        case BLE_GAP_EVT_SEC_PARAMS_REQUEST:
            // Pairing not supported
            err_code = sd_ble_gap_sec_params_reply(m_conn_handle, BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP, NULL, NULL);
            APP_ERROR_CHECK(err_code);
            break; // BLE_GAP_EVT_SEC_PARAMS_REQUEST

        case BLE_GATTS_EVT_SYS_ATTR_MISSING:
            // No system attributes have been stored.
            err_code = sd_ble_gatts_sys_attr_set(m_conn_handle, NULL, 0, 0);
            APP_ERROR_CHECK(err_code);
            break; // BLE_GATTS_EVT_SYS_ATTR_MISSING

        case BLE_GATTC_EVT_TIMEOUT:
            // Disconnect on GATT Client timeout event.
            err_code = sd_ble_gap_disconnect(p_ble_evt->evt.gattc_evt.conn_handle,
                                             BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            APP_ERROR_CHECK(err_code);
            break; // BLE_GATTC_EVT_TIMEOUT

        case BLE_GATTS_EVT_TIMEOUT:
            // Disconnect on GATT Server timeout event.
            err_code = sd_ble_gap_disconnect(p_ble_evt->evt.gatts_evt.conn_handle,
                                             BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            APP_ERROR_CHECK(err_code);
            break; // BLE_GATTS_EVT_TIMEOUT

        case BLE_EVT_USER_MEM_REQUEST:
            err_code = sd_ble_user_mem_reply(p_ble_evt->evt.gattc_evt.conn_handle, NULL);
            APP_ERROR_CHECK(err_code);
            break; // BLE_EVT_USER_MEM_REQUEST

        case BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST:
        {
            ble_gatts_evt_rw_authorize_request_t  req;
            ble_gatts_rw_authorize_reply_params_t auth_reply;

            req = p_ble_evt->evt.gatts_evt.params.authorize_request;

            if (req.type != BLE_GATTS_AUTHORIZE_TYPE_INVALID)
            {
                if ((req.request.write.op == BLE_GATTS_OP_PREP_WRITE_REQ)     ||
                    (req.request.write.op == BLE_GATTS_OP_EXEC_WRITE_REQ_NOW) ||
                    (req.request.write.op == BLE_GATTS_OP_EXEC_WRITE_REQ_CANCEL))
                {
                    if (req.type == BLE_GATTS_AUTHORIZE_TYPE_WRITE)
                    {
                        auth_reply.type = BLE_GATTS_AUTHORIZE_TYPE_WRITE;
                    }
                    else
                    {
                        auth_reply.type = BLE_GATTS_AUTHORIZE_TYPE_READ;
                    }
                    auth_reply.params.write.gatt_status = APP_FEATURE_NOT_SUPPORTED;
                    err_code = sd_ble_gatts_rw_authorize_reply(p_ble_evt->evt.gatts_evt.conn_handle,
                                                               &auth_reply);
                    APP_ERROR_CHECK(err_code);
                }
            }
        } break; // BLE_GATTS_EVT_RW_AUTHORIZE_REQUEST

#if (NRF_SD_BLE_API_VERSION == 3)
        case BLE_GATTS_EVT_EXCHANGE_MTU_REQUEST:
            err_code = sd_ble_gatts_exchange_mtu_reply(p_ble_evt->evt.gatts_evt.conn_handle,
                                                       NRF_BLE_MAX_MTU_SIZE);
            APP_ERROR_CHECK(err_code);
            break; // BLE_GATTS_EVT_EXCHANGE_MTU_REQUEST
#endif

        default:
            // No implementation needed.
            break;
    }
}


/**@brief Function for dispatching a SoftDevice event to all modules with a SoftDevice
 *        event handler.
 *
 * @details This function is called from the SoftDevice event interrupt handler after a
 *          SoftDevice event has been received.
 *
 * @param[in] p_ble_evt  SoftDevice event.
 */
static void ble_evt_dispatch(ble_evt_t * p_ble_evt)
{
//	NRF_LOG_RAW_INFO(NRF_LOG_COLOR_CODE_GREEN"BLE EVT %X\n", p_ble_evt->header.evt_id);

    ble_conn_params_on_ble_evt(p_ble_evt);
	ble_mi_on_ble_evt(p_ble_evt);
	ble_lock_on_ble_evt(p_ble_evt);
    ble_nus_on_ble_evt(&m_nus, p_ble_evt);
    on_ble_evt(p_ble_evt);
    ble_advertising_on_ble_evt(p_ble_evt);
    bsp_btn_ble_on_ble_evt(p_ble_evt);

}

/**@brief Function for dispatching a system event to interested modules.
 *
 * @details This function is called from the System event interrupt handler after a system
 *          event has been received.
 *
 * @param[in] sys_evt  System stack event @ NRF_SOC_EVTS.
 */
static void sys_evt_dispatch(uint32_t sys_evt)
{
    // Dispatch the system event to the fstorage module, where it will be
    // dispatched to the Flash Data Storage (FDS) module.
    fs_sys_event_handler(sys_evt);

    // Dispatch to the Advertising module last, since it will check if there are any
    // pending flash operations in fstorage. Let fstorage process system events first,
    // so that it can report correctly to the Advertising module.
    ble_advertising_on_sys_evt(sys_evt);
}

/**@brief Function for the SoftDevice initialization.
 *
 * @details This function initializes the SoftDevice and the BLE event interrupt.
 */
static void ble_stack_init(void)
{
    uint32_t err_code;

    nrf_clock_lf_cfg_t clock_lf_cfg = {.source        = NRF_CLOCK_LF_SRC_XTAL,
	                                   .rc_ctiv       = 0,
	                                   .rc_temp_ctiv  = 0,
	                                   .xtal_accuracy = NRF_CLOCK_LF_XTAL_ACCURACY_100_PPM};

    // Initialize SoftDevice.
    SOFTDEVICE_HANDLER_INIT(&clock_lf_cfg, NULL);

    ble_enable_params_t ble_enable_params;
    err_code = softdevice_enable_get_default_config(CENTRAL_LINK_COUNT,
                                                    PERIPHERAL_LINK_COUNT,
                                                    &ble_enable_params);
    APP_ERROR_CHECK(err_code);
	ble_enable_params.common_enable_params.vs_uuid_count = 4;
    //Check the ram settings against the used number of links
    CHECK_RAM_START_ADDR(CENTRAL_LINK_COUNT,PERIPHERAL_LINK_COUNT);

    // Enable BLE stack.
#if (NRF_SD_BLE_API_VERSION == 3)
    ble_enable_params.gatt_enable_params.att_mtu = NRF_BLE_MAX_MTU_SIZE;
#endif

#if (IS_SRVC_CHANGED_CHARACT_PRESENT == 1)
    ble_enable_params.gatts_enable_params.service_changed = 1;
#endif

    err_code = softdevice_enable(&ble_enable_params);
    APP_ERROR_CHECK(err_code);

    // Subscribe for BLE events.
    err_code = softdevice_ble_evt_handler_set(ble_evt_dispatch);
    APP_ERROR_CHECK(err_code);

    // Subscribe for SOC events.
	err_code = softdevice_sys_evt_handler_set(sys_evt_dispatch);
    APP_ERROR_CHECK(err_code);
}


/**@brief Function for handling events from the BSP module.
 *
 * @param[in]   event   Event generated by button press.
 */
void bsp_event_handler(bsp_event_t event)
{
    uint32_t err_code;
    switch (event)
    {
        case BSP_EVENT_SLEEP:
            sleep_mode_enter();
            break;

        case BSP_EVENT_DISCONNECT:
            err_code = sd_ble_gap_disconnect(m_conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            if (err_code != NRF_ERROR_INVALID_STATE)
            {
                APP_ERROR_CHECK(err_code);
            }
            break;

        case BSP_EVENT_WHITELIST_OFF:
            if (m_conn_handle == BLE_CONN_HANDLE_INVALID)
            {
                err_code = ble_advertising_restart_without_whitelist();
                if (err_code != NRF_ERROR_INVALID_STATE)
                {
                    APP_ERROR_CHECK(err_code);
                }
            }
            break;

        default:
            break;
    }
}



/**@brief Function for initializing the Advertising functionality.
 */
static void advertising_init(void)
{
    uint32_t               err_code;
    uint8_t                data[27];
    uint8_t                total_len;
	ble_gap_addr_t         dev_mac;

	mibeacon_capability_t cap = {.connectable = 1,
	                             .encryptable = 1,
	                             .bondAbility = 1};

#if (NRF_SD_BLE_API_VERSION == 3)
	sd_ble_gap_addr_get(&dev_mac);
#else
	sd_ble_gap_address_get(&dev_mac);
#endif

	mibeacon_config_t  beacon_cfg     = {0};
	beacon_cfg.frame_ctrl.version     = 4;
	beacon_cfg.pid                    = APP_PRODUCT_ID;
	beacon_cfg.p_capability           = &cap;
	beacon_cfg.p_mac                  = dev_mac.addr;
	
	mibeacon_data_set(&beacon_cfg, data, &total_len);

    /* Indicating Mi Service */
	ble_advdata_service_data_t serviceData;
    serviceData.service_uuid = BLE_UUID_MI_SERVICE;
    serviceData.data.size    = total_len;
    serviceData.data.p_data  = data;
	
    // Build advertising data struct to pass into @ref ble_advertising_init.
    ble_advdata_t          advdata;
    memset(&advdata, 0, sizeof(advdata));
    advdata.name_type          = BLE_ADVDATA_NO_NAME;
    advdata.include_appearance = false;
    advdata.flags              = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;
    advdata.p_service_data_array = &serviceData;
    advdata.service_data_count = 1;

    ble_advdata_t          scanrsp;
    memset(&scanrsp, 0, sizeof(scanrsp));
	scanrsp.name_type               = BLE_ADVDATA_FULL_NAME;
    scanrsp.uuids_complete.uuid_cnt = sizeof(m_adv_uuids) / sizeof(m_adv_uuids[0]);
    scanrsp.uuids_complete.p_uuids  = m_adv_uuids;

	ble_adv_modes_config_t options;
    memset(&options, 0, sizeof(options));
    options.ble_adv_fast_enabled  = true;
    options.ble_adv_fast_interval = APP_ADV_INTERVAL;
    options.ble_adv_fast_timeout  = APP_ADV_TIMEOUT_IN_SECONDS;

    err_code = ble_advertising_init(&advdata, NULL, &options, on_adv_evt, NULL);
    APP_ERROR_CHECK(err_code);

}

/**@brief Function for initializing buttons and leds.
 *
 * @param[out] p_erase_bonds  Will be true if the clear bonding button was pressed to wake the application up.
 */
static void buttons_leds_init(bool * p_erase_bonds)
{
    bsp_event_t startup_event;

    uint32_t err_code = bsp_init(BSP_INIT_LED | BSP_INIT_BUTTONS,
                                 APP_TIMER_TICKS(100, APP_TIMER_PRESCALER),
                                 bsp_event_handler);
    APP_ERROR_CHECK(err_code);

    err_code = bsp_btn_ble_init(NULL, &startup_event);
    APP_ERROR_CHECK(err_code);

    *p_erase_bonds = (startup_event == BSP_EVENT_CLEAR_BONDING_DATA);
}

/**@brief Function for placing the application in low power state while waiting for events.
 */
static void power_manage(void)
{
    uint32_t err_code = sd_app_evt_wait();
    APP_ERROR_CHECK(err_code);
}

/**
 * @brief TWI events handler.
 */
void twi0_handler(nrf_drv_twi_evt_t const * p_event, void * p_context)
{
     switch (p_event->type)
    {
        case NRF_DRV_TWI_EVT_DONE:
			NRF_LOG_INFO("TWI evt done: %d\n", p_event->xfer_desc.type);
            m_twi0_xfer_done = true;
            break;
        default:
			NRF_LOG_ERROR("TWI evt error %d.\n", p_event->type);
            break;
    }
}

void twi0_init (void)
{
    ret_code_t err_code;

    const nrf_drv_twi_config_t msc_config = {
       .scl                = 28,
       .sda                = 29,
       .frequency          = NRF_TWI_FREQ_100K,
       .interrupt_priority = APP_IRQ_PRIORITY_HIGH,
       .clear_bus_init     = true
    };

    err_code = nrf_drv_twi_init(&TWI0, &msc_config, twi0_handler, NULL);
    APP_ERROR_CHECK(err_code);

    nrf_drv_twi_enable(&TWI0);
}

void time_init(struct tm * time_ptr);

typedef struct {
	uint8_t did[8];
	uint8_t version[12];

	union {
		uint8_t LTMK[16];
		uint8_t MKPK[16];
	};

	uint8_t cloud_key[16];
	uint8_t beacon_key[16];
	
	struct {
		uint8_t factory_new;
		uint8_t reserved[3];
	}status;

} mi_sysinfo_t;

mi_sysinfo_t mi_sysinfo;

typedef __packed struct {
	uint8_t  action;
	uint8_t  method;
	uint32_t user_id;
	uint32_t time;
} lock_evt_t;

void mi_schd_event_handler(schd_evt_t evt_id)
{
	NRF_LOG_RAW_INFO("USER CUSTOM CALLBACK RECV EVT ID %d\n", evt_id);
}

void poll_timer_handler(void * p_context)
{
	time_t utc_time = time(NULL);
	NRF_LOG_RAW_INFO(NRF_LOG_COLOR_CODE_GREEN"%s", nrf_log_push(ctime(&utc_time)));

	uint8_t battery_stat = 70;
	mibeacon_obj_enque(MI_STA_LOCK, sizeof(battery_stat), &battery_stat);

	NRF_LOG_RAW_INFO("max timer cnt :%d\n", app_timer_op_queue_utilization_get());
}
/**@brief Application main function.
 */
int main(void)
{
    uint32_t errno;
    bool erase_bonds;
	uint8_t  lock_opcode = 1;
	lock_evt_t lock_event;

	NRF_LOG_INIT(NULL);
	NRF_LOG_RAW_INFO(RTT_CTRL_CLEAR"Compiled  %s %s\n", (uint32_t)__DATE__, (uint32_t)__TIME__);

    // Initialize.
    APP_TIMER_INIT(APP_TIMER_PRESCALER, APP_TIMER_OP_QUEUE_SIZE, false);

	twi0_init();
	time_init(NULL);

    buttons_leds_init(&erase_bonds);
    ble_stack_init();
    gap_params_init();

    services_init();
    advertising_init();
    conn_params_init();

	/* <!> mi_psm_init() must be called after ble_stack_init(). */
	mi_psm_init();
	mibeacon_init();
	mi_scheduler_init(APP_TIMER_TICKS(10, APP_TIMER_PRESCALER), mi_schd_event_handler);

	app_timer_create(&poll_timer, APP_TIMER_MODE_REPEATED, poll_timer_handler);
	app_timer_start(poll_timer, APP_TIMER_TICKS(20000, APP_TIMER_PRESCALER), NULL);
	
#ifdef M_TEST
	mi_scheduler_start(0);
#else
	sd_power_mode_set(NRF_POWER_MODE_LOWPWR);
	sd_power_dcdc_mode_set(NRF_POWER_DCDC_ENABLE);
	sd_ble_gap_tx_power_set(0);
    errno = ble_advertising_start(BLE_ADV_MODE_FAST);
    APP_ERROR_CHECK(errno);
#endif

    // Enter main loop.
    for (;;)
    {
		if (get_lock_opcode(&lock_opcode) == 0) {
			switch(lock_opcode) {
				case 0:
					NRF_LOG_INFO(" unlock \n");
					bsp_board_led_off(3);

					lock_event.action = 0;
					lock_event.method = 0;
					lock_event.user_id= get_mi_key_id();
					lock_event.time   = time(NULL);

					mibeacon_obj_enque(MI_EVT_LOCK, sizeof(lock_event), &lock_event);
					break;
				
				case 1:
					NRF_LOG_INFO(" lock \n");
					bsp_board_led_on(3);

					lock_event.action = 1;
					lock_event.method = 0;
					lock_event.user_id= get_mi_key_id();
					lock_event.time   = time(NULL);

					mibeacon_obj_enque(MI_EVT_LOCK, sizeof(lock_event), &lock_event);
					break;

				case 2:
					NRF_LOG_INFO(" bolt \n");
					bsp_board_led_off(3);

					lock_event.action = 2;
					lock_event.method = 0;
					lock_event.user_id= get_mi_key_id();
					lock_event.time   = time(NULL);

					mibeacon_obj_enque(MI_EVT_LOCK, sizeof(lock_event), &lock_event);
					break;

				default:
					NRF_LOG_ERROR("lock opcode error %d", lock_opcode);

			}
			
			send_lock_stat(lock_opcode);
			send_lock_log((uint8_t *)&lock_event, sizeof(lock_event));
			lock_opcode = 0;
		}

		if (NRF_LOG_PROCESS() == false)
        {
            power_manage();
        }
    }
}


void app_error_fault_handler(uint32_t id, uint32_t pc, uint32_t info)
{
	error_info_t* pinfo = (error_info_t *)info;
	char * const p_str = (void *)(pinfo->p_file_name);
    NRF_LOG_ERROR(" Oops ! ");

    switch (id)
    {
        case NRF_FAULT_ID_SDK_ASSERT:
			NRF_LOG_RAW_INFO("ERROR at %s : %d\n", nrf_log_push(p_str),
			                                       pinfo->line_num  );
            break;

        case NRF_FAULT_ID_SDK_ERROR:
			NRF_LOG_RAW_INFO("ERRNO %d at %s : %d\n", pinfo->err_code,
			                                          nrf_log_push(p_str),
			                                          pinfo->line_num);
            break;
    }

    NRF_LOG_FINAL_FLUSH();

    // On assert, the system can only recover with a reset.
#ifndef DEBUG
    NVIC_SystemReset();
#else
    app_error_save_and_stop(id, pc, info);
#endif // DEBUG
}

/**
 * @}
 */
