#include "nrf_soc.h"
#include "ble_gap.h"
#include "mi_type.h"

int arch_rand_get(uint8_t *p_rand, uint8_t n)
{
	while(sd_rand_application_vector_get(p_rand, n) != NRF_SUCCESS);
	return 0;
}

int arch_dev_mac_get(uint8_t *p_mac, uint8_t n)
{
	ble_gap_addr_t   dev_mac;

	#if (NRF_SD_BLE_API_VERSION == 3)
        sd_ble_gap_addr_get(&dev_mac);
    #else
        sd_ble_gap_address_get(&dev_mac);
    #endif
	
	memcpy(p_mac, dev_mac.addr, 6);
	return 0;
}
