#### Hardware Platform
* nRF51-DK PCA10028 
* nRF52-DK PCA10040

#### Requirement
- arm MDK 5.25
- SEGGER Jlink
- Git

#### How to use

1. download nRF5 SDK 12.3.0 [here](http://www.nordicsemi.com/eng/nordic/Products/nRF52832/nRF5-SDK-v12-zip/54281)
2. $ cd SDK_12.3.0\examples\ble_peripheral\ directory.
3. $ git clone --recursive https://github.com/MiEcosystem/mijia_ble_secure.git
3. change PRODUCT_ID to your product ID (i.e. pid), that you got when registered in [Mi IoT](https://iot.mi.com/index.html).

#### Diagnose

Make sure you have installed JLink.

$ JLinkExe -device NRF51422_XXAA -if swd -speed 8000

Then open a new terminal tab:

$ telnet 127.0.0.1 19021

The log infomation will be print in this telnet session.