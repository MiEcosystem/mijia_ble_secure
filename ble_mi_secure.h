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

#ifndef BLE_MI_SECURE_H__
#define BLE_MI_SECURE_H__

#include "ble.h"
#include "ble_srv_common.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_UUID_MI_SERVICE 0xFE95                      /**< The UUID of the Xiaomi Service. */
#define BLE_MI_MAX_DATA_LEN (GATT_MTU_SIZE_DEFAULT - 3) /**< Maximum length of data (in bytes) that can be transmitted to the peer by the Xiaomi  service module. */

/**@brief Xiaomi Service event handler type. */
typedef void (*ble_mi_data_handler_t) (uint8_t * p_data, uint16_t length);

/**@brief Xiaomi Service initialization structure.
 *
 * @details This structure contains the initialization information for the service. The application
 * must fill this structure and pass it to the service using the @ref ble_mi_init
 *          function.
 */
typedef struct
{
    ble_mi_data_handler_t data_handler; /**< Event handler to be called for handling received data. */
} ble_mi_init_t;

/**@brief Xiaomi Service structure.
 *
 * @details This structure contains status information related to the service.
 */
typedef struct {
    uint8_t                  uuid_type;               /**< UUID type for Xiaomi Service Base UUID. */
    uint16_t                 service_handle;          /**< Handle of Xiaomi Service (as provided by the SoftDevice). */
    ble_gatts_char_handles_t auth_handles;            /**< Handles related to the characteristic (as provided by the SoftDevice). */
    ble_gatts_char_handles_t pubkey_handles;              
    ble_gatts_char_handles_t buffer_handles;
              
    uint16_t                 conn_handle;             /**< Handle of the current connection (as provided by the SoftDevice). BLE_CONN_HANDLE_INVALID if not in a connection. */
    bool                     is_notification_enabled; /**< Variable to indicate if the peer has enabled notification of the RX characteristic.*/
    ble_mi_data_handler_t    data_handler;            /**< Event handler to be called for handling received data. */
    ble_mi_data_handler_t    pubkey_rxd_handler;     /**< Event handler to be called for handling received data. */
    ble_mi_data_handler_t    buffer_rxd_handler;     /**< Event handler to be called for handling received data. */
} ble_mi_t;

/**@brief Function for initializing the Xiaomi Service.
 *
 * @param[in] p_mi_s_init  Information needed to initialize the service.
 *
 * @retval NRF_SUCCESS If the service was successfully initialized. Otherwise, an error code is returned.
 * @retval NRF_ERROR_NULL If either of the pointers p_mi_s or p_mi_s_init is NULL.
 */
uint32_t ble_mi_init(const ble_mi_init_t * p_mi_s_init);

/**@brief Function for handling the Xiaomi Service's BLE events.
 *
 * @details The Xiaomi Service expects the application to call this function each time an
 * event is received from the SoftDevice. This function processes the event if it
 * is relevant and calls the Xiaomi Service event handler of the
 * application if necessary.
 *
 * @param[in] p_ble_evt   Event received from the SoftDevice.
 */
void ble_mi_on_ble_evt(ble_evt_t * p_ble_evt);

/**@brief Function for sending a string to the peer.
 *
 * @details This function sends the input string as an RX characteristic notification to the
 *          peer.
 *
 * @param[in] p_string    String to be sent.
 * @param[in] length      Length of the string.
 *
 * @retval NRF_SUCCESS If the string was sent successfully. Otherwise, an error code is returned.
 */
uint32_t ble_mi_string_send(uint8_t * p_string, uint16_t length);

#ifdef __cplusplus
}
#endif

#endif // BLE_MI_SECURE_H__

/** @} */
