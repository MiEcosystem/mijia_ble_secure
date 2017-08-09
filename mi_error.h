#ifndef __MI_ERROR_H
#define __MI_ERROR_H

#ifdef __cplusplus
extern "C"
{
#endif

#define MI_ERROR_BASE_NUM                     0

#define MI_SUCCESS                           (MI_ERROR_BASE_NUM + 0)  ///< Successful command

#define MI_ERROR_SOFTDEVICE_NOT_ENABLED      (MI_ERROR_BASE_NUM + 2)  ///< SoftDevice has not been enabled
#define MI_ERROR_INTERNAL                    (MI_ERROR_BASE_NUM + 3)  ///< Internal Error
#define MI_ERROR_NO_MEM                      (MI_ERROR_BASE_NUM + 4)  ///< No Memory for operation
#define MI_ERROR_NOT_FOUND                   (MI_ERROR_BASE_NUM + 5)  ///< Not found
#define MI_ERROR_NOT_SUPPORTED               (MI_ERROR_BASE_NUM + 6)  ///< Not supported

#define MI_ERROR_INVALID_PARAM               (MI_ERROR_BASE_NUM + 7)  ///< Invalid Parameter
#define MI_ERROR_INVALID_STATE               (MI_ERROR_BASE_NUM + 8)  ///< Invalid state, operation disallowed in this state
#define MI_ERROR_INVALID_LENGTH              (MI_ERROR_BASE_NUM + 9)  ///< Invalid Length
#define MI_ERROR_INVALID_FLAGS               (MI_ERROR_BASE_NUM + 10) ///< Invalid Flags
#define MI_ERROR_INVALID_DATA                (MI_ERROR_BASE_NUM + 11) ///< Invalid Data

#define MI_ERROR_DATA_SIZE                   (MI_ERROR_BASE_NUM + 12) ///< Invalid Data size
#define MI_ERROR_TIMEOUT                     (MI_ERROR_BASE_NUM + 13) ///< Operation timed out
#define MI_ERROR_NULL                        (MI_ERROR_BASE_NUM + 14) ///< Null Pointer
#define MI_ERROR_FORBIDDEN                   (MI_ERROR_BASE_NUM + 15) ///< Forbidden Operation
#define MI_ERROR_INVALID_ADDR                (MI_ERROR_BASE_NUM + 16) ///< Bad Memory Address
#define MI_ERROR_BUSY                        (MI_ERROR_BASE_NUM + 17) ///< Busy
#define MI_ERROR_CONN_COUNT                  (MI_ERROR_BASE_NUM + 18) ///< Maximum connection count exceeded.
#define MI_ERROR_RESOURCES                   (MI_ERROR_BASE_NUM + 19) ///< Not enough resources for operation


#ifdef __cplusplus
}
#endif



#endif  /* END OF __MI_ERROR_H */ 


