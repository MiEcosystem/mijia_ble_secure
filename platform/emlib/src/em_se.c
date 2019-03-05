/***************************************************************************//**
 * @file
 * @brief Secure Element API
 * @version 5.7.2
 *******************************************************************************
 * # License
 * <b>Copyright 2018 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * SPDX-License-Identifier: Zlib
 *
 * The licensor of this software is Silicon Laboratories Inc.
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 ******************************************************************************/
#include "em_device.h"

#if defined(SEMAILBOX_PRESENT)

#include "em_se.h"
#include "em_assert.h"

/***************************************************************************//**
 * @addtogroup emlib
 * @{
 ******************************************************************************/

/***************************************************************************//**
 * @addtogroup SE
 * @{
 ******************************************************************************/

/*******************************************************************************
 ******************************   DEFINES    ***********************************
 ******************************************************************************/

/* OTP initialization structure defines. */
#define SE_OTP_MCU_SETTINGS_FLAG_SECURE_BOOT_ENABLE (1 << 16)
#define SE_OTP_MCU_SETTINGS_FLAG_SECURE_BOOT_VERIFY_CERTIFICATE (1 << 17)
#define SE_OTP_MCU_SETTINGS_FLAG_SECURE_BOOT_ANTI_ROLLBACK (1 << 18)

/*******************************************************************************
 **************************   GLOBAL FUNCTIONS   *******************************
 ******************************************************************************/

/***************************************************************************//**
 * @brief
 *   Add input data to a command
 *
 * @details
 *   This function adds a buffer of input data to the given SE command structure
 *   The buffer gets appended by reference at the end of the list of already
 *   added buffers.
 *
 * @note
 *   Note that this function does not copy either the data buffer or the buffer
 *   structure, so make sure to keep the data object in scope until the command
 *   has been executed by the secure element.
 *
 * @param[in]  command
 *   Pointer to an SE command structure.
 *
 * @param[in]  data
 *   Pointer to a data transfer structure.
 ******************************************************************************/
void SE_addDataInput(SE_Command_t *command, SE_DataTransfer_t *data)
{
  if (command->data_in == NULL) {
    command->data_in = data;
  } else {
    SE_DataTransfer_t *next = command->data_in;
    while (next->next != (void*)SE_DATATRANSFER_STOP) {
      next = (SE_DataTransfer_t*)next->next;
    }
    next->next = data;
  }
}

/***************************************************************************//**
 * @brief
 *   Add output data to a command
 *
 * @details
 *   This function adds a buffer of output data to the given SE command structure
 *   The buffer gets appended by reference at the end of the list of already
 *   added buffers.
 *
 * @note
 *   Note that this function does not copy either the data buffer or the buffer
 *   structure, so make sure to keep the data object in scope until the command
 *   has been executed by the secure element.
 *
 * @param[in]  command
 *   Pointer to an SE command structure.
 *
 * @param[in]  data
 *   Pointer to a data transfer structure.
 ******************************************************************************/
void SE_addDataOutput(SE_Command_t *command,
                      SE_DataTransfer_t *data)
{
  if (command->data_out == NULL) {
    command->data_out = data;
  } else {
    SE_DataTransfer_t *next = command->data_out;
    while (next->next != (void*)SE_DATATRANSFER_STOP) {
      next = (SE_DataTransfer_t*)next->next;
    }
    next->next = data;
  }
}

/***************************************************************************//**
 * @brief
 *   Add a parameter to a command
 *
 * @details
 *   This function adds a parameter word to the passed command.
 *
 * @note
 *   Make sure to not exceed @ref SE_MAX_PARAMETERS.
 *
 * @param[in]  command
 *   Pointer to a filled-out SE command structure.
 * @param[in]  parameter
 *   Parameter to add.
 ******************************************************************************/
void SE_addParameter(SE_Command_t *command, uint32_t parameter)
{
  if (command->num_parameters >= SE_MAX_PARAMETERS) {
    EFM_ASSERT(command->num_parameters < SE_MAX_PARAMETERS);
    return;
  }

  command->parameters[command->num_parameters] = parameter;
  command->num_parameters += 1;
}

/***************************************************************************//**
 * @brief
 *   Execute the passed command
 *
 * @details
 *   This function starts the execution of the passed command by the secure
 *   element. When started, wait for the RXINT interrupt flag, or call
 *   @ref SE_waitCommandCompletion to busy-wait. After completion, you have to
 *   call @ref SE_readCommandResponse to get the command's execution status.
 *
 * @param[in]  command
 *   Pointer to a filled-out SE command structure.
 ******************************************************************************/
void SE_executeCommand(SE_Command_t *command)
{
  // Don't overflow our struct
  if (command->num_parameters > SE_MAX_PARAMETERS) {
    EFM_ASSERT(command->num_parameters <= SE_MAX_PARAMETERS);
    return;
  }

  // Wait for room available in the mailbox
  while (!(SEMAILBOX_HOST->TX_STATUS & SEMAILBOX_TX_STATUS_TXINT)) ;

  // Write header to start transaction
  SEMAILBOX_HOST->TX_HEADER = sizeof(uint32_t) * (4 + command->num_parameters);

  // Write command into FIFO
  SEMAILBOX_HOST->FIFO[0].DATA = command->command;

  // Write DMA descriptors into FIFO
  SEMAILBOX_HOST->FIFO[0].DATA = (uint32_t)command->data_in;
  SEMAILBOX_HOST->FIFO[0].DATA = (uint32_t)command->data_out;

  // Write applicable parameters into FIFO
  for (size_t i = 0; i < command->num_parameters; i++) {
    SEMAILBOX_HOST->FIFO[0].DATA = command->parameters[i];
  }

  return;
}

/***************************************************************************//**
 * @brief
 *   Writes data to User Data section in MTP. Write data must be aligned to words
 *    and contain a number of bytes that is divisable by four.
 * @note
 *   It is recommended to erase the flash page before performing a write.
 *
 * @param[in] offset
 *   Offset to the flash word to write to. Must be aligned to words.
 * @param[in] data
 *   Data to write to flash.
 * @param[in] numBytes
 *   Number of bytes to write to flash. NB: Must be divisable by four.
 * @return
 *   One of the SE_RESPONSE return codes.
 * @retval SE_RESPONSE_OK when the command was executed successfully or a
 *                        signature was successfully verified,
 * @retval SE_RESPONSE_INVALID_COMMAND when the command ID was not recognized,
 * @retval SE_RESPONSE_AUTHORIZATION_ERROR when the command is not authorized,
 * @retval SE_RESPONSE_INVALID_SIGNATURE when signature verification failed,
 * @retval SE_RESPONSE_BUS_ERROR when a bus error was thrown during the command,
 *                               e.g. because of conflicting Secure/Non-Secure
 *                               memory accesses,
 * @retval SE_RESPONSE_CRYPTO_ERROR on an internal SE failure, or
 * @retval SE_RESPONSE_INVALID_PARAMETER when an invalid parameter was passed
 ******************************************************************************/
SE_Response_t SE_writeUserData(uint32_t offset,
                               void *data,
                               uint32_t numBytes)
{
  // SE command structures
  SE_Command_t command = SE_COMMAND_DEFAULT(SE_COMMAND_WRITE_USER_DATA);
  SE_DataTransfer_t userData = SE_DATATRANSFER_DEFAULT(data, numBytes);

  SE_addDataInput(&command, &userData);

  SE_addParameter(&command, offset);
  SE_addParameter(&command, numBytes);

  SE_executeCommand(&command);
  SE_Response_t res = SE_readCommandResponse();
  return res;
}

/***************************************************************************//**
 * @brief
 *   Erases User Data section in MTP.
 * @return
 *   One of the SE_RESPONSE return codes.
 * @retval SE_RESPONSE_OK when the command was executed successfully or a
 *                        signature was successfully verified,
 * @retval SE_RESPONSE_INVALID_COMMAND when the command ID was not recognized,
 * @retval SE_RESPONSE_AUTHORIZATION_ERROR when the command is not authorized,
 * @retval SE_RESPONSE_INVALID_SIGNATURE when signature verification failed,
 * @retval SE_RESPONSE_BUS_ERROR when a bus error was thrown during the command,
 *                               e.g. because of conflicting Secure/Non-Secure
 *                               memory accesses,
 * @retval SE_RESPONSE_CRYPTO_ERROR on an internal SE failure, or
 * @retval SE_RESPONSE_INVALID_PARAMETER when an invalid parameter was passed
 ******************************************************************************/
SE_Response_t SE_eraseUserData()
{
  // SE command structures
  SE_Command_t command = SE_COMMAND_DEFAULT(SE_COMMAND_ERASE_USER_DATA);

  SE_addParameter(&command, SE_COMMAND_OPTION_ERASE_UD);
  SE_executeCommand(&command);
  SE_Response_t res = SE_readCommandResponse();
  return res;
}

/***************************************************************************//**
 * @brief
 *   Returns the current boot status, versions and system configuration.
 *
 * @param[out] status
 *   SE_Status_t containing current SE status.
 *
 * @return
 *   One of the SE_RESPONSE return codes.
 * @retval SE_RESPONSE_OK upon command completion. Errors are encoded in the
 *                        different parts of the returned status object.
 ******************************************************************************/
SE_Response_t SE_getStatus(SE_Status_t *status)
{
  volatile uint32_t output[9] = { 0 };

  // SE command structures
  SE_Command_t command = SE_COMMAND_DEFAULT(SE_COMMAND_GET_STATUS);
  SE_DataTransfer_t outData = SE_DATATRANSFER_DEFAULT((void*)output, 4 * 9);

  SE_addDataOutput(&command, &outData);

  // Execute command and return response
  SE_executeCommand(&command);
  SE_Response_t res = SE_readCommandResponse();

  // Update status object
  status->bootStatus = output[4];
  status->seFwVersion = output[5];
  status->hostFwVersion = output[6];

  SE_DebugStatus_t debugStatus;
  debugStatus.debugLockEnabled = (output[7] & (1 << 0));
  debugStatus.deviceEraseEnabled = (output[7] & (1 << 1));
  debugStatus.secureDebugEnabled = (output[7] & (1 << 2));
  status->debugStatus = debugStatus;

  status->secureBootEnabled = ((output[8] & 0x1) && ((output[8] & ~0x1) == 0));

  return res;
}

/***************************************************************************//**
 * @brief
 *   Read the serial number of the SE module.
 *
 * @param[out] serial
 *   Pointer to array of size 16 bytes.
 *
 * @return
 *   One of the SE_Response_t return codes.
 * @retval SE_RESPONSE_OK when serial number is returned successfully,
 * @retval SE_RESPONSE_INTERNAL_ERROR if not.
 ******************************************************************************/
SE_Response_t SE_serialNumber(void *serial)
{
  // SE command structures
  SE_Command_t command = SE_COMMAND_DEFAULT(SE_COMMAND_READ_SERIAL);
  SE_DataTransfer_t outData = SE_DATATRANSFER_DEFAULT(serial, 16);

  SE_addDataOutput(&command, &outData);

  // Execute command and return response
  SE_executeCommand(&command);
  SE_Response_t res = SE_readCommandResponse();
  return res;
}

/***************************************************************************//**
 * @brief
 *   Read pubkey or pubkey signature.
 *
 * @details
 *   Read out a public key stored in the SE, or its signature. The command can
 *   be used to read:
 *   * SE_KEY_TYPE_BOOT
 *   * SE_KEY_TYPE_AUTH
 *
 * @param[in] key_type
 *   ID of key type to read.
 *
 * @param[out] pubkey
 *   Pointer to a buffer to contain the returned public key.
 *   Must be word aligned and have a length of 64 bytes.
 *
 * @param[in] numBytes
 *   Length of pubkey buffer (64 bytes).
 *
 * @param[in] signature
 *   If true, read signature for the requested key type instead of the public
 *   key.
 *
 * @return
 *   One of the SE_RESPONSE return codes.
 * @retval SE_RESPONSE_OK when the command was executed successfully
 * @retval SE_RESPONSE_TEST_FAILED when the pubkey is not set
 * @retval SE_RESPONSE_INVALID_PARAMETER when an invalid type is passed
 ******************************************************************************/
SE_Response_t SE_readPubkey(uint32_t key_type, void *pubkey, uint32_t numBytes, bool signature)
{
  EFM_ASSERT((key_type == SE_KEY_TYPE_BOOT)
             || (key_type == SE_KEY_TYPE_AUTH));

  EFM_ASSERT(numBytes == 64);
  EFM_ASSERT(!((size_t)pubkey & 3U));

  // SE command structures
  uint32_t commandWord =
    (signature) ? SE_COMMAND_READ_PUBKEY_SIGNATURE : SE_COMMAND_READ_PUBKEY;
  SE_Command_t command = SE_COMMAND_DEFAULT(commandWord | key_type);

  SE_DataTransfer_t pubkeyData = SE_DATATRANSFER_DEFAULT(pubkey, numBytes);
  SE_addDataOutput(&command, &pubkeyData);

  SE_executeCommand(&command);
  SE_Response_t res = SE_readCommandResponse();
  return res;
}

/***************************************************************************//**
 * @brief
 *   Init pubkey or pubkey signature.
 *
 * @details
 *   Initialize public key stored in the SE, or its signature. The command can
 *   be used to write:
 *   * SE_KEY_TYPE_BOOT
 *   * SE_KEY_TYPE_AUTH
 *
 * @note
 *   These keys can not be overwritten, so this command can only be issued once
 *   per key per part.
 *
 * @param[in] key_type
 *   ID of key type to initialize.
 *
 * @param[in] pubkey
 *   Pointer to a buffer that contains the public key or signature.
 *   Must be word aligned and have a length of 64 bytes.
 *
 * @param[in] numBytes
 *   Length of pubkey buffer (64 bytes).
 *
 * @param[in] signature
 *   If true, initialize signature for the requested key type instead of the
 *   public key.
 *
 * @return
 *   One of the SE_RESPONSE return codes.
 * @retval SE_RESPONSE_OK when the command was executed successfully
 * @retval SE_RESPONSE_TEST_FAILED when the pubkey is not set
 * @retval SE_RESPONSE_INVALID_PARAMETER when an invalid type is passed
 ******************************************************************************/
SE_Response_t SE_initPubkey(uint32_t key_type, void *pubkey, uint32_t numBytes, bool signature)
{
  EFM_ASSERT((key_type == SE_KEY_TYPE_BOOT)
             || (key_type == SE_KEY_TYPE_AUTH));

  EFM_ASSERT(numBytes == 64);
  EFM_ASSERT(!((size_t)pubkey & 3U));

  // Find parity word
  volatile uint32_t parity = 0;
  for (size_t i = 0; i < numBytes / 4; i++) {
    parity = parity ^ ((uint32_t *)pubkey)[i];
  }

  // SE command structures
  uint32_t commandWord =
    (signature) ? SE_COMMAND_INIT_PUBKEY_SIGNATURE : SE_COMMAND_INIT_PUBKEY;
  SE_Command_t command = SE_COMMAND_DEFAULT(commandWord | key_type);

  SE_DataTransfer_t parityData = SE_DATATRANSFER_DEFAULT(&parity, 4);
  SE_addDataInput(&command, &parityData);

  SE_DataTransfer_t pubkeyData = SE_DATATRANSFER_DEFAULT(pubkey, numBytes);
  SE_addDataInput(&command, &pubkeyData);

  SE_executeCommand(&command);
  SE_Response_t res = SE_readCommandResponse();
  return res;
}

/***************************************************************************//**
 * @brief
 *   Initialize SE OTP configuration.
 * @return
 *   One of the SE_RESPONSE return codes.
 * @retval SE_RESPONSE_OK when the command was executed successfully
 ******************************************************************************/
SE_Response_t SE_initOTP(SE_OTPInit_t *otp_init)
{
  volatile uint32_t mcuSettingsFlags = 0;

  SE_Response_t res;

  if (otp_init->enableSecureBoot) {
    mcuSettingsFlags |= SE_OTP_MCU_SETTINGS_FLAG_SECURE_BOOT_ENABLE;

    uint8_t pubkey[64];
    res = SE_readPubkey(SE_KEY_TYPE_BOOT, &pubkey, 64, false);
    if (res != SE_RESPONSE_OK) {
      return SE_RESPONSE_ABORT;
    }
  }
  if (otp_init->verifySecureBootCertificate) {
    mcuSettingsFlags |= SE_OTP_MCU_SETTINGS_FLAG_SECURE_BOOT_VERIFY_CERTIFICATE;
  }
  if (otp_init->enableAntiRollback) {
    mcuSettingsFlags |= SE_OTP_MCU_SETTINGS_FLAG_SECURE_BOOT_ANTI_ROLLBACK;
  }

  volatile struct ReservedSettings {
    uint8_t reserved1[16];
    uint8_t reserved2[2];
    uint8_t reserved3[2];
  } reservedSettings = {
    { 0x00 },
    { 0xFF },
    { 0x00 }
  };

  // Find parity word
  uint32_t parity = 0;
  parity = parity ^ mcuSettingsFlags;
  for (size_t i = 0; i < 5; i++) {
    parity = parity ^ ((uint32_t*)(&reservedSettings))[i];
  }

  // SE command structures
  SE_Command_t command = SE_COMMAND_DEFAULT(SE_COMMAND_INIT_OTP);

  volatile uint32_t parameters[2] = {
    parity,
    sizeof(mcuSettingsFlags)
    + sizeof(reservedSettings)
  };
  SE_DataTransfer_t parametersData = SE_DATATRANSFER_DEFAULT(&parameters, 8);
  SE_addDataInput(&command, &parametersData);

  SE_DataTransfer_t mcuSettingsFlagsData = SE_DATATRANSFER_DEFAULT(&mcuSettingsFlags, sizeof(mcuSettingsFlags));
  SE_addDataInput(&command, &mcuSettingsFlagsData);

  SE_DataTransfer_t reservedSettingsData = SE_DATATRANSFER_DEFAULT(&reservedSettings, sizeof(reservedSettings));
  SE_addDataInput(&command, &reservedSettingsData);

  SE_executeCommand(&command);
  res = SE_readCommandResponse();

  return res;
}

/***************************************************************************//**
 * @brief
 *   Returns the current debug lock configuration.
 * @param[out] status
 *   The command returns a DebugStatus_t with the current status of the
 *   debug configuration.
 * @return
 *   One of the SE_RESPONSE return codes.
 * @retval SE_RESPONSE_OK when the command was executed successfully.
 * @retval SE_RESPONSE_INTERNAL_ERROR if there are configuration errors.
 ******************************************************************************/
SE_Response_t SE_debugLockStatus(SE_DebugStatus_t *status)
{
  SE_Response_t res;

  // SE command structures
  SE_Command_t command = SE_COMMAND_DEFAULT(SE_COMMAND_DBG_LOCK_STATUS);

  volatile uint32_t status_word = 0;
  SE_DataTransfer_t statusData = SE_DATATRANSFER_DEFAULT((void*)&status_word, 4);
  SE_addDataOutput(&command, &statusData);

  SE_executeCommand(&command);
  res = SE_readCommandResponse();

  status->debugLockEnabled = (status_word & (1 << 0));
  status->deviceEraseEnabled = (status_word & (1 << 1));
  status->secureDebugEnabled = (status_word & (1 << 2));

  return res;
}

/***************************************************************************//**
 * @brief
 *   Enables the debug lock for the part.
 * @details
 *   The debug port will be closed and the only way to open it is through
 *   device erase (if enabled) or through secure debug unlock (if enabled).
 * @return
 *   One of the SE_RESPONSE return codes.
 * @retval SE_RESPONSE_OK when the command was executed successfully.
 * @retval SE_RESPONSE_INTERNAL_ERROR there was a problem locking the debug port.
 ******************************************************************************/
SE_Response_t SE_debugLockApply()
{
  SE_Command_t command = SE_COMMAND_DEFAULT(SE_COMMAND_DBG_LOCK_APPLY);
  SE_executeCommand(&command);

  return SE_readCommandResponse();
}

/***************************************************************************//**
 * @brief
 *   Enables the secure debug functionality.
 * @details
 *   Enables the secure debug functionality that can be used to open a locked
 *   debug port through the Get challenge and Open debug commands. This command
 *   can only be executed before the debug port is locked, and after a secure
 *   debug public key has been installed in the SE.
 * @return
 *   One of the SE_RESPONSE return codes.
 * @retval SE_RESPONSE_OK when the command was executed successfully.
 * @retval SE_RESPONSE_INVALID_COMMAND if debug port is locked.
 * @retval SE_RESPONSE_INVALID_PARAMETER if secure debug certificates are
 *                                       missing.
 * @retval SE_RESPONSE_INTERNAL_ERROR if there was a problem during execution.
 ******************************************************************************/
SE_Response_t SE_debugSecureEnable()
{
  SE_Command_t command = SE_COMMAND_DEFAULT(SE_COMMAND_DBG_LOCK_ENABLE_SECURE);
  SE_executeCommand(&command);

  return SE_readCommandResponse();
}

/***************************************************************************//**
 * @brief
 *   Disables the secure debug functionality.
 * @details
 *   Disables the secure debug functionality that can be used to open a
 *   locked debug port.
 * @return
 *   One of the SE_RESPONSE return codes.
 * @retval SE_RESPONSE_OK when the command was executed successfully.
 * @retval SE_RESPONSE_INTERNAL_ERROR if there was a problem during execution.
 ******************************************************************************/
SE_Response_t SE_debugSecureDisable()
{
  SE_Command_t command = SE_COMMAND_DEFAULT(SE_COMMAND_DBG_LOCK_DISABLE_SECURE);
  SE_executeCommand(&command);

  return SE_readCommandResponse();
}

/***************************************************************************//**
 * @brief
 *   Performs a device mass erase and debug unlock.
 *
 * @details
 *   Performs a device mass erase and resets the debug configuration to its
 *   initial unlocked state. Only available before DEVICE_ERASE_DISABLE has
 *   been executed.
 *
 * @note
 *   This command clears and verifies the complete flash and ram of the
 *   system, excluding the user data pages and one-time programmable
 *   commissioning information in the secure element.
 *
 * @return
 *   One of the SE_RESPONSE return codes.
 * @retval SE_RESPONSE_OK when the command was executed successfully.
 * @retval SE_RESPONSE_INVALID_COMMAND if device erase is disabled.
 * @retval SE_RESPONSE_INTERNAL_ERROR if there was a problem during execution.
 ******************************************************************************/
SE_Response_t SE_deviceErase()
{
  SE_Command_t command = SE_COMMAND_DEFAULT(SE_COMMAND_DEVICE_ERASE);
  SE_executeCommand(&command);

  return SE_readCommandResponse();
}

/***************************************************************************//**
 * @brief
 *   Disabled device erase functionality.
 *
 * @details
 *   This command disables the device erase command. It does not lock the
 *   debug interface to the part, but it is a permanent action for the part.
 *   If device erase is disabled and the device is debug locked, there is no
 *   way to permanently unlock the part. If secure debug unlock is enabled,
 *   secure debug unlock can still be used to temporarily open the debug port.
 *
 * @warning
 *   This command permanently disables the device erase functionality!
 *
 * @return
 *   One of the SE_RESPONSE return codes.
 * @retval SE_RESPONSE_OK when the command was executed successfully.
 * @retval SE_RESPONSE_INTERNAL_ERROR if there was a problem during execution.
 ******************************************************************************/
SE_Response_t SE_deviceEraseDisable()
{
  SE_Command_t command = SE_COMMAND_DEFAULT(SE_COMMAND_DEVICE_ERASE_DISABLE);
  SE_executeCommand(&command);

  return SE_readCommandResponse();
}

/** @} (end addtogroup SE) */
/** @} (end addtogroup emlib) */

#endif /* defined(SEMAILBOX_PRESENT) */
