工程同步到 SDK 12.2.0\examples\ble_peripheral\ 目录下即可
硬件平台： nRF51-DK PCA10028
		   nRF52-DK PCA10040
		   
PROFILE
------------------------
nRF52   bytes    time(us)
------------------------
aesecb  16         25
aesccm  16        150
        32        200
hkdf    32        340
		64        780
------------------------
nRF51   bytes    time(us)
------------------------
aesecb  16         61
aesccm  16        520
        32        670
	    64        980
hkdf    32       3400
		64		 5800
memcpy 256         40
memset 256        120