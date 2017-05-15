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

void mi_schedulor(void * p_context);
int mi_schedulor_init(uint32_t interval);
int mi_schedulor_start(uint32_t *p_context);
int mi_schedulor_stop(int type);

#ifdef __cplusplus
}
#endif

#endif // BLE_MI_SECURE_H__

/** @} */
