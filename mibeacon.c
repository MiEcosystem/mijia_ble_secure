/**************************************************************************************************
  Filename:       mibeacon.c
  Description:    This file contains the implementation of mi beacon.
  
**************************************************************************************************/

/*********************************************************************
 * INCLUDES
 */
#include <string.h>
#include "nordic_common.h"
#include "ble_srv_common.h"
#include "app_util.h"
#include "app_error.h"

#include "mibeacon.h"

/*********************************************************************
 * MACROS
 */

/*********************************************************************
 * CONSTANTS
 */
#define MIBEACON_MAX_EVENT_LEN         10
#define MIBEACON_MAX_ADV_LEN           27

#define MIBEACON_FC_VERSION_BITS       0xf000


/*********************************************************************
 * TYPEDEFS
 */

/*********************************************************************
 * GLOBAL VARIABLES
 */


/*********************************************************************
 * EXTERNAL VARIABLES
 */

/*********************************************************************
 * EXTERNAL FUNCTIONS
 */


/*********************************************************************
 * LOCAL VARIABLES
 */
static uint16_t mibeacon_frameCtrl;
static uint8_t  mibeacon_capability;
static uint8_t  mibeacon_mac[B_ADDR_LEN];
static uint8_t  mibeacon_evt[MIBEACON_MAX_EVENT_LEN];
static uint8_t  mibeacon_evtLen ;
static uint8_t  mibeacon_title[MIBEACON_MAX_EVENT_LEN];
static uint8_t  mibeacon_titleLen ;
static uint8_t  mibeacon_mfData[MIBEACON_MAX_EVENT_LEN] ;
static uint8_t  mibeacon_mfDataLen;
static uint16_t mibeacon_productID;
static uint8_t  mibeacon_frameCounter;



#define FRM_CTRL_SET(bit)            (mibeacon_frameCtrl |= bit)
#define FRM_CTRL_CLR(bit)            (mibeacon_frameCtrl &= ~bit)
#define FRM_CTRL_GET(bit)            (mibeacon_frameCtrl & bit)
#define FRM_CTRL_VERSION_SET(v)      (mibeacon_frameCtrl |= ((v<<12) & MIBEACON_FC_VERSION_BITS))



static uint8_t mibeacon_getLen(void)
{
    uint8_t len = MIBEACON_MIN_LEN;
    if (FRM_CTRL_GET(MIBEACON_ITEM_MAC_INCLUDE)) {

        len += 6;
    }

    if (FRM_CTRL_GET(MIBEACON_ITEM_CAP_INCLUDE)) {

        len += 1;
    }

    if (FRM_CTRL_GET(MIBEACON_ITEM_EVT_INCLUDE)) {

        len += mibeacon_evtLen;
    }

    if (FRM_CTRL_GET(MIBEACON_ITEM_MIHOME_TITLE_INCLUDE)) {

        len += mibeacon_titleLen;
    }

    if (FRM_CTRL_GET(MIBEACON_ITEM_MANUFACTORY_DATA_INCLUDE)) {

        len += mibeacon_mfDataLen;
    }

    if (FRM_CTRL_GET(MIBEACON_ITEM_SEC_ENABLE)) {
        len += 3;
    }

    return len;
}


static mi_sts_t mibeacon_verifyLen(uint8_t len)
{
    if (len > MIBEACON_MAX_ADV_LEN) {
        return MI_ERR_LEN_TOO_LONG;
    }

    return MI_SUCCESS;
}


/*
 * mibeacon_set - API to set mi beacon parameters
 *
 * @param   item - ID of optional parameters
 * @param   data - adv data of specified mi beacon item
 * @param   len  - len of the data
 */
mi_sts_t mibeacon_set(uint16_t item, uint8_t* data, uint8_t len)
{
    if (MIBEACON_ITEM_PRODUCT_ID == item) {
        memcpy((uint8_t*)&mibeacon_productID, data, 2);
        return MI_SUCCESS;
    }

    if (MIBEACON_ITEM_VERSION == item) {
        if (!data) 
            FRM_CTRL_VERSION_SET(0);
        else  
            FRM_CTRL_VERSION_SET(*data);
        return MI_SUCCESS;
    }
    

    if (*data) {
        FRM_CTRL_SET(item);
    } else {
        FRM_CTRL_CLR(item);
    }

    //mibeacon_frameCounter++;
            
    switch (item) {
        case MIBEACON_ITEM_FACTORY_NEW:
        case MIBEACON_ITEM_CONNECTED:
        case MIBEACON_ITEM_CENTRAL:
        case MIBEACON_ITEM_SEC_ENABLE:
        case MIBEACON_ITEM_BINDING_CFM:
            break;

        case MIBEACON_ITEM_MAC_INCLUDE:
            if (data) {
                memcpy(mibeacon_mac, data, B_ADDR_LEN);
            } else {
                memset(mibeacon_mac, 0, B_ADDR_LEN);
            }
            break;


        case MIBEACON_ITEM_CAP_INCLUDE:
            if (data) {
                mibeacon_capability = *data;
            }
            break;


        case MIBEACON_ITEM_EVT_INCLUDE:
            if (data) {
                memcpy(mibeacon_evt, data, len);
                mibeacon_evtLen = len;
            }
            break;


        case MIBEACON_ITEM_MIHOME_TITLE_INCLUDE:
            if (data) {
                memcpy(mibeacon_title, data, len);
                mibeacon_titleLen = len;
            }
            break;


        case MIBEACON_ITEM_MANUFACTORY_DATA_INCLUDE:
            if (data) {
                memcpy(mibeacon_mfData, data, len);
                mibeacon_mfDataLen = len;
            }
            break;

        default:
            break;
    }

    return MI_SUCCESS;
}



/*
 * mibeacon_append   - Append mi beacon data to user adv data.
 *
 * @param   advData  - The pointer of user advertising data.
 * @param   len      - The length of user advertising data.
 * @param   totalLen - The total length after append the Mi beacon
 *
 * @return  Status.
 */
mi_sts_t mibeacon_append(uint8_t* advData, uint8_t len, uint8_t* totalLen)
{
    mi_sts_t ret = MI_SUCCESS;
    uint8_t* p = NULL;
    uint8_t  mibeacon_len;
    
    /* Verify the length first */
    mibeacon_len = mibeacon_getLen();
    *totalLen = mibeacon_len + len;
    ret = mibeacon_verifyLen(*totalLen);
    if (MI_SUCCESS != ret) {
        return ret;
    }

    mibeacon_len = mibeacon_getLen();

    /* Get free adv data len */
    p = advData + len;

    /* Append mandatory data */
    *p++ = LO_UINT16(mibeacon_frameCtrl);
    *p++ = HI_UINT16(mibeacon_frameCtrl);

    *p++ = LO_UINT16(mibeacon_productID);
    *p++ = HI_UINT16(mibeacon_productID);

    *p++ = mibeacon_frameCounter++;


    /* Append option data*/
    if (FRM_CTRL_GET(MIBEACON_ITEM_MAC_INCLUDE)) {
        memcpy(p, mibeacon_mac, B_ADDR_LEN);
        p += 6;
    }

    if (FRM_CTRL_GET(MIBEACON_ITEM_CAP_INCLUDE)) {
        *p++ = mibeacon_capability;
    }

    if (FRM_CTRL_GET(MIBEACON_ITEM_EVT_INCLUDE)) {
        memcpy(p, mibeacon_evt, mibeacon_evtLen);
        p += mibeacon_evtLen;
    }

    if (FRM_CTRL_GET(MIBEACON_ITEM_MIHOME_TITLE_INCLUDE)) {
        memcpy(p, mibeacon_title, mibeacon_titleLen);
        p += mibeacon_titleLen;
    }

    if (FRM_CTRL_GET(MIBEACON_ITEM_MANUFACTORY_DATA_INCLUDE)) {
        memcpy(p, mibeacon_mfData, mibeacon_mfDataLen);
        p += mibeacon_mfDataLen;
    }

    return MI_SUCCESS;
}


mi_sts_t mibeacon_set_and_append(uint16_t item, uint8_t* data, uint8_t len, uint8_t* advData, uint8_t advLen, uint8_t* totalLen)
{
    mi_sts_t status = MI_SUCCESS;
    
    // Set Beacon Item first
    status = mibeacon_set(item, data, len);
    if (MI_SUCCESS != status) {
        goto error;     
    }
    
    status = mibeacon_append(advData, advLen, totalLen);
    if (status != MI_SUCCESS) {
        goto error;
    }
    
error:
    return status;
}




