#!/bin/bash
firmware=("iot_dir880l_110b01")

cd Docker
bash allreset.sh
cd ..

pkill -f python

# 存取語法：必須使用 ${變數名[索引]} 的格式
python3 ./Firmware/sentMQTT.py "${firmware[0]}" &
python3 ./Firmware/openfirmware.py "${firmware[0]}"