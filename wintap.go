package wintap

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	TAP_IOCTL_CONFIG_POINT_TO_POINT = TAP_CONTROL_CODE(5, 0)
	TAP_IOCTL_SET_MEDIA_STATUS      = TAP_CONTROL_CODE(6, 0)
	TAP_IOCTL_CONFIG_TUN            = TAP_CONTROL_CODE(10, 0)
)

func CTL_CODE(device_type, function, method, access uint32) uint32 {
	return (device_type << 16) | (access << 14) | (function << 2) | method
}

func TAP_CONTROL_CODE(request, method uint32) uint32 {
	return CTL_CODE(34, request, method, 0)
}

func GetTapGuid() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}`, registry.READ)
	if err != nil {
		return ""
	}
	defer key.Close()
	kns, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return ""
	}
	for _, k := range kns {
		subkey, err := registry.OpenKey(key, k, registry.READ)
		if err != nil {
			continue
		}
		cid, _, err := subkey.GetStringValue("ComponentId")
		if err != nil {
			continue
		}
		if cid == "tap0901" {
			guid, _, err := subkey.GetStringValue("NetCfgInstanceId")
			if err != nil {
				continue
			}
			return guid
		}
	}
	return ""
}

func GetTapHandle() (windows.Handle, error) {
	guid := GetTapGuid()
	if guid == "" {
		return 0, fmt.Errorf("Please install TAP-Windows Adapter first!")
	}
	name, _ := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\Global\%s.tap`, guid))
	access := uint32(windows.GENERIC_READ | windows.GENERIC_WRITE)
	mode := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE)
	return windows.CreateFile(name, access, mode, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_SYSTEM, 0)
}

func InitTap(h windows.Handle) error {
	var bytesReturned uint32
	cmd := []byte{1, 0, 0, 0}
	err := windows.DeviceIoControl(h, TAP_IOCTL_SET_MEDIA_STATUS, &cmd[0], uint32(len(cmd)), nil, 0, &bytesReturned, nil)
	if err != nil {
		return err
	}
	cmd = []byte{0x0a, 0x03, 0x00, 0x01, 0x0a, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00}
	return windows.DeviceIoControl(h, TAP_IOCTL_CONFIG_TUN, &cmd[0], uint32(len(cmd)), nil, 0, &bytesReturned, nil)
}
