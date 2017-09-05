/**@file
 *
 * @defgroup ble_mi Xiaomi Service
 * @{
 * @ingroup  ble_sdk_srv
 * @brief    Xiaomi Service implementation.
 *
 * @details The Xiaomi Service is a simple GATT-based service with many characteristics.
 *          Data received from the peer is passed to the application, and the data received
 *          from the application of this service is sent to the peer as Handle Value
 *          Notifications. This module demonstrates how to implement a custom GATT-based
 *          service and characteristics using the SoftDevice. The service
 *          is used by the application to send and receive pub_key and MSC Cert to and from the
 *          peer.
 *
 * @note The application must propagate SoftDevice events to the Xiaomi Service module
 *       by calling the ble_mi_on_ble_evt() function from the ble_stack_handler callback.
 */

#ifndef MI_SECURE_H__
#define MI_SECURE_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define REG_TYPE                       0x10UL
#define REG_START                      (REG_TYPE)
#define REG_SUCCESS                    (REG_TYPE+1)
#define REG_FAILED                     (REG_TYPE+2)

#define LOG_TYPE                       0x20UL
#define LOG_START                      (LOG_TYPE)
#define LOG_SUCCESS                    (LOG_TYPE+1)
#define LOG_FAILED                     (LOG_TYPE+2)

#define SHARED_TYPE                    0x30UL
#define SHARED_LOG_START               (SHARED_TYPE)
#define SHARED_LOG_START_W_CERT        (SHARED_TYPE+4)
#define SHARED_LOG_SUCCESS             (SHARED_TYPE+1)
#define SHARED_LOG_FAILED              (SHARED_TYPE+2)
#define SHARED_LOG_EXPIRED             (SHARED_TYPE+3)

typedef enum {
	UNAUTHORIZATION = 0,
	OWNER_AUTHORIZATION,
	SHARE_AUTHORIZATION
} mi_author_stat_t;

typedef enum {
	SCHD_EVT_REG_SUCCESS = 0x01,
	SCHD_EVT_REG_FAILED,
	SCHD_EVT_ADMIN_LOGIN_SUCCESS,
	SCHD_EVT_ADMIN_LOGIN_FAILED,
	SCHD_EVT_SHARE_LOGIN_SUCCESS,
	SCHD_EVT_SHARE_LOGIN_FAILED,
	SCHD_EVT_TIMEOUT
} schd_evt_t;

typedef void (*mi_schd_event_handler_t)(schd_evt_t evt_id);
void set_mi_authorization(mi_author_stat_t status);
uint32_t get_mi_authorization(void);
uint32_t get_mi_key_id(void);
uint32_t mi_scheduler_init(uint32_t interval, mi_schd_event_handler_t handler);
uint32_t mi_scheduler_start(uint32_t status);
uint32_t mi_scheduler_stop(int type);

#ifdef __cplusplus
}
#endif

#endif // BLE_MI_SECURE_H__

/** @} */
