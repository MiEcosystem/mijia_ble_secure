Hardware Platform
======
Silicon Labs WSTK 4001 with 4104A EFR32BG13 Core board

Requirement
======
- Simiplicity Studio IDE
- SEGGER Jlink
- Git

How to use
======
Before you type the command below, make sure you can access the submodule repos (mijia ble libs).
```bash
$ git clone --recursive https://github.com/MiEcosystem/mijia_ble_secure.git -b silabs
```
then import the project in Simiplicity Studio IDE.

A mijia security chip is required for xiaomi BLE secure authentication. This project will take the default BSP_IIC0 (SCL PC10 / SDA PC11) as the IIC port that communicate with security chip.


Diagnose
======
### unix-like
Install JLink and add it to your path. <br>
```bash
$ JLinkExe -device EFR32BG13PXXXF512 -if swd -speed 8000 -RTTTelnetPort 4000
```
Then open a new terminal tab and execute:
```bash
$ telnet 127.0.0.1 4000
```
You will find the log information in this telnet session.

### windows 
Use the J-Link RTT Viewer to get those log information.