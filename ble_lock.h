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

#ifndef BLE_LOCK_H__
#define BLE_LOCK_H__

#include "ble.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__CC_ARM)
  #pragma anon_unions
#elif defined(__ICCARM__)
  #pragma language=extended
#elif defined(__GNUC__)
  /* anonymous unions are enabled by default */
#endif


/**@brief Function for initializing the Lock Service.
 *
 * @param[in] p_mi_s_init  Information needed to initialize the service.
 *
 * @retval NRF_SUCCESS If the service was successfully initialized. Otherwise, an error code is returned.
 * @retval NRF_ERROR_NULL If either of the pointers p_mi_s or p_mi_s_init is NULL.
 */
uint32_t ble_lock_init();

/**@brief Function for handling the Lock Service's BLE events.
 *
 * @details The Lock Service expects the application to call this function each time an
 * event is received from the SoftDevice. This function processes the event if it
 * is relevant and calls the Lock Service event handler of the
 * application if necessary.
 *
 * @param[in] p_ble_evt   Event received from the SoftDevice.
 */
void ble_lock_on_ble_evt(ble_evt_t * p_ble_evt);

#ifdef __cplusplus
}
#endif

#endif // BLE_LOCK_H__

/** @} */
