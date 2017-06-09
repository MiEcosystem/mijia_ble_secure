#ifndef __MI_TYPE_H
#define __MI_TYPE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#define BLE_MAC_LEN    6

#define MISERVICE_UUID                                0xFE95

/**
 * MI Beacon minium length.
 * Including len(1) + type(1) + serviceUUID(2) + FrameCtrl(2) + Product ID(2)
 */
#define MIBEACON_MIN_LEN                              5

/**
 * MI Beacon status and error code.
 */
typedef enum
{
    MI_SUCCESS = 0,
    MI_ERR_INVALID_PARA,
    MI_ERR_LEN_TOO_LONG,
    MI_ERR_NO_MEM,
} mi_retcode_t;


#define HI_UINT16(a) (((a) >> 8) & 0xFF)
#define LO_UINT16(a) ((a) & 0xFF)


#ifdef __cplusplus
}
#endif



#endif  /* END OF __MI_TYPE_H */ 


