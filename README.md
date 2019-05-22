Hardware Platform
======
Silicon Labs WSTK 4001 with 4104A EFR32BG13 Core board

Requirement
======
- [Simiplicity Studio IDE](https://www.silabs.com/products/development-tools/software/simplicity-studio)
- [SEGGER Jlink](https://www.segger.com/downloads/jlink/)
- [Git](https://git-scm.com/downloads)

How to use
======
Before you type the command below, make sure you can access the [**mijia ble libs**](https://github.com/MiEcosystem/mijia_ble_libs) repo.
```bash
$ git clone --recursive https://github.com/MiEcosystem/mijia_ble_secure.git -b silabs
```
then import the project in Simiplicity Studio IDE.

A mijia security chip is required for Xiaomi BLE secure authentication. This project will take the default BSP_IIC0 (SCL PC10 / SDA PC11) as the IIC port that communicate with security chip.


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

More Documents
======
### Fundamentals
* [UG103.14: BLE Fundamentals](https://www.silabs.com/documents/login/user-guides/ug103-14-fundamentals-ble.pdf)
* [UG136: Silicon Labs Bluetooth C Application Developer's Guide](https://www.silabs.com/documents/login/user-guides/ug136-ble-c-soc-dev-guide.pdf)

### Quick Start Guide
* [QSG139: Getting Started with Bluetooth Software Development](https://www.silabs.com/documents/login/quick-start-guides/qsg139-getting-started-with-bluetooth.pdf)
