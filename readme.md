## 支持的硬件平台

- nRF52832-DK PCA10040
- nRF52840-DK PCA10056

nRF51硬件请参考[nordic_legacy分支](https://github.com/MiEcosystem/mijia_ble_secure/tree/nordic_legacy)

## 使用说明

1. 下载 [nRF5 SDK 15.2.0](https://www.nordicsemi.com/Software-and-Tools/Software/nRF5-SDK/Download#infotabs)
2. 由于 15.2.0 SDK 自带 nrfx twim driver 存在 bug, 需下载 [nrfx 1.2.0](https://github.com/NordicSemiconductor/nrfx/releases/tag/v1.2.0) 并替换原 SDK/modules/nrfx 
3. 进入到文件目录 SDK_15.2.0\examples\ble_peripheral\
4. 执行 git clone --recursive https://github.com/MiEcosystem/mijia_ble_secure.git -b nordic

更多信息请参考[米家高安全级接入产品开发](https://github.com/MiEcosystem/miio_open/tree/master/ble)
