import os
from pathlib import Path

home = os.path.expanduser("~")
current_dir = os.path.join(home, Path(__file__).resolve().parent)

fap_config = os.path.join(current_dir,"Firmware_tool/firmware-analysis-plus/fap.config")
firmadyne_config = os.path.join(current_dir,"Firmware_tool/firmware-analysis-plus/firmadyne/firmadyne.config")

firmadyne = os.path.join(current_dir, "Firmware_tool/firmware-analysis-plus/firmadyne")

with open(fap_config, 'r') as f:
    lines = f.readlines()

# 直接替換該行內容
lines[2] = "firmadyne_path=" + firmadyne

with open(fap_config, 'w') as f:
    f.writelines(lines)

with open(firmadyne_config, 'r') as f:
    lines = f.readlines()

# 直接替換該行內容
lines[3] = "FIRMWARE_DIR=" + firmadyne + "\n"

with open(firmadyne_config, 'w') as f:
    f.writelines(lines)