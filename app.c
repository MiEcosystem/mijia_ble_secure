/***************************************************************************//**
 * @file app.c
 * @brief Silicon Labs Empty Example Project
 *
 * This example demonstrates the bare minimum needed for a Blue Gecko C application
 * that allows Over-the-Air Device Firmware Upgrading (OTA DFU). The application
 * starts advertising after boot and restarts advertising after a connection is closed.
 *******************************************************************************
 * # License
 * <b>Copyright 2018 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

/* Bluetooth stack headers */
#include "bg_types.h"
#include "native_gecko.h"
#include "gatt_db.h"

#include "app.h"

/* mijia ble  */
#include "mible_api.h"
#include "mible_log.h"

/* Main application */
void appMain(gecko_configuration_t *pconfig)
{
#if DISABLE_SLEEP
  pconfig->sleep.flags = 0;
#endif

  MI_LOG_INFO(RTT_CTRL_CLEAR"\n");
  MI_LOG_INFO("Compiled %s %s\n", __DATE__, __TIME__);
  MI_LOG_INFO("system clock %d Hz\n", SystemCoreClockGet());

  /* Initialize stack */
  gecko_stack_init(pconfig);
  gecko_bgapi_class_system_init();
  gecko_bgapi_class_le_gap_init();
  gecko_bgapi_class_gatt_server_init();
  gecko_bgapi_class_hardware_init();
  gecko_bgapi_class_flash_init();

  while (1) {
    /* Event pointer for handling events */
    struct gecko_cmd_packet* evt;

    /* Check for stack event. This is a blocking event listener. If you want non-blocking please see UG136. */
    evt = gecko_wait_event();

    /* Handle events */
    switch (BGLIB_MSG_ID(evt->header)) {
      /* This boot event is generated when the system boots up after reset.
       * Do not call any stack commands before receiving the boot event.
       * Here the system is set to start advertising immediately after boot procedure. */
      case gecko_evt_system_boot_id:
        break;

      case gecko_evt_le_connection_opened_id:
        break;

      case gecko_evt_le_connection_closed_id:
        break;

      /* Add additional event handlers as your application requires */

      default:
        break;
    }
  }
}
