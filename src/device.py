import hashlib
import os
import platform

import psutil


class DeviceBinder:
    def get_device_id(self, folder):
        if platform.system() == "Windows":
            drive = os.path.splitdrive(folder)[0]
            for part in psutil.disk_partitions():
                if part.device.startswith(drive):
                    return hashlib.sha256(part.device.encode()).hexdigest()
        elif platform.system() == "Linux":
            import pyudev
            context = pyudev.Context()
            for device in context.list_devices(subsystem='block', DEVTYPE='partition'):
                if device.device_node and folder.startswith(device.device_node):
                    return hashlib.sha256(device.device_node.encode()).hexdigest()
        else:
            return hashlib.sha256(folder.encode()).hexdigest()
