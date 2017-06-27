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

void mi_scheduler(void * p_context);
int mi_scheduler_init(uint32_t interval);
int mi_scheduler_start(uint32_t *p_context);
int mi_scheduler_stop(int type);

#define REG_TYPE            0x10UL
#define REG_START    	    (REG_TYPE)
#define REG_SUCCESS 	    (REG_TYPE+1)
#define REG_FAILED	        (REG_TYPE+2)

#define LOG_TYPE 	        0x20UL
#define LOG_START	        (LOG_TYPE)
#define LOG_SUCCESS      	(LOG_TYPE+1)
#define LOG_FAILED	        (LOG_TYPE+2)

#define SHARED_TYPE     	0x30UL
#define SHARED_LOG_START	(SHARED_TYPE)
#define SHARED_LOG_SUCCESS	(SHARED_TYPE+1)
#define SHARED_LOG_FAILED	(SHARED_TYPE+2)
#define SHARED_LOG_EXPIRED	(SHARED_TYPE+3)

#define UPDATE_NONCE_TYPE   0x80UL
#define UPDATE_APPNONCE_REQ (UPDATE_NONCE_TYPE)
#define UPDATE_APPNONCE_RSP (UPDATE_NONCE_TYPE+1)
#define UPDATE_DEVNONCE_REQ (UPDATE_NONCE_TYPE+2)
#define UPDATE_DEVNONCE_RSP (UPDATE_NONCE_TYPE+3)


void mi_scheduler(void * p_context);
int mi_scheduler_init(uint32_t interval);
int mi_scheduler_start(uint32_t status);
int mi_scheduler_stop(int type);

#ifdef __cplusplus
}
#endif

#endif // BLE_MI_SECURE_H__

/** @} */
