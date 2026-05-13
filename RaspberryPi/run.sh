#!/bin/bash
firmware=("iot_dir880l_110b01", "dir601_revB_FW_201")

cd Docker
bash allreset.sh
cd ..

pkill -f python

# 存取語法：必須使用 ${變數名[索引]} 的格式
python3 ./Firmware/sentMQTT.py "${firmware[1]}" &
python3 ./Firmware/openfirmware.py "${firmware[1]}"