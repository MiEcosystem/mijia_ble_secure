
#ifndef _MI_H
#define _MI_H

#ifdef __cplusplus
extern "C"
{
#endif
	
/**
 * Definition for BLE address length.
 */
#define B_ADDR_LEN    6	


/**
 * MI Beacon status and error code.
 */
typedef enum mi_sts
{
    MI_SUCCESS,
    MI_ERR_INVALID_PARA,
    MI_ERR_LEN_TOO_LONG,
    MI_ERR_NO_MEM,
} mi_sts_t;


#define HI_UINT16(a) (((a) >> 8) & 0xFF)
#define LO_UINT16(a) ((a) & 0xFF)


#ifdef __cplusplus
}
#endif



#endif  /* _MI_H */ 


