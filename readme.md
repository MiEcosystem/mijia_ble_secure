# Hardware Platform
- nRF52832-DK PCA10040
- nRF52840-DK PCA10056

# Requirement
- arm MDK 5.25
- SEGGER Jlink
- Git

# How to use

1. You need to download nRF5 SDK 15.2.0 from [here](https://www.nordicsemi.com/eng/nordic/Products/nRF52-DK/nRF5-SDK-zip/59014)
2. $ cd SDK_15.2.0\examples\ble_peripheral\ directory.
3. $ git clone --recursive https://github.com/MiEcosystem/mijia_ble_secure.git -b nordic
3. change PRODUCT_ID to your product ID (i.e. pid), that you got when registered in [Mi IoT](https://iot.mi.com/index.html).

# Diagnose

Make sure you have installed JLink and add it to your path.

$ JLinkExe -device NRF52832_XXAA -if swd -speed 1000 -RTTTelnetPort 2000

Then open a new terminal tab and iuput:

$ telnet 127.0.0.1 2000

The log infomation will be print in this telnet session.