package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"log"
	"os"
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
	buf := make([]byte, 4096)
	cmd := []byte{1, 0, 0, 0}
	err := windows.DeviceIoControl(h, TAP_IOCTL_SET_MEDIA_STATUS, &cmd[0], uint32(len(cmd)), &buf[0], uint32(len(buf)), &bytesReturned, nil)
	if err != nil {
		return fmt.Errorf("[error 1] handle:%d, %s, %d, %v", h, err.Error(), TAP_IOCTL_SET_MEDIA_STATUS, cmd)
	}
	cmd = []byte{0x0a, 0x03, 0x00, 0x01, 0x0a, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00}
	err = windows.DeviceIoControl(h, TAP_IOCTL_CONFIG_TUN, &cmd[0], uint32(len(cmd)), &buf[0], uint32(len(buf)), &bytesReturned, nil)
	if err != nil {
		return fmt.Errorf("[error 2] handle:%d, %s, %d, %v", h, err.Error(), TAP_IOCTL_CONFIG_TUN, cmd)
	}
	return nil
}

func main() {
	h, err := GetTapHandle()
	if err != nil {
		panic(err)
		os.Exit(1)
	}
	defer windows.CloseHandle(h)
	err = InitTap(h)
	if err != nil {
		panic(err)
		os.Exit(1)
	}
	x := 0
	//var n uint32
	buf := make([]byte, 4096)
	log.Println("Starting TAP records...")
	for {
		n, err := windows.Read(h, buf)
		//err = windows.ReadFile(h, buf, &n, nil)
		if err != nil {
			fmt.Println(err.Error())
		}
		x++
		log.Println("Read Packet", x, n)
		//fmt.Println(buf[:n])

		eth := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.Lazy)

		/*
			if net := eth.NetworkLayer(); net != nil {
				src, dst := net.NetworkFlow().Endpoints()
				if src == dst {
					fmt.Println(src, dst)
				}
			}
		*/
		//netFlow := eth.NetworkLayer().NetworkFlow()
		//src, dst := netFlow.Endpoints()
		//fmt.Println(src, dst)

		fmt.Println(eth.Dump())

		//fmt.Println(buf[:12], buf[16:20], buf[12:16], buf[20:n])
		//fmt.Println(eth.ApplicationLayer().LayerContents())

		if layer := eth.Layer(layers.LayerTypeDNS); layer != nil {
			fmt.Println("This is a DNS packet!")
			dns, _ := layer.(*layers.DNS)
			fmt.Printf("%v\n", dns)
			continue
		}

		if layer := eth.Layer(layers.LayerTypeIPv4); layer != nil {
			fmt.Println("This is a IPv4 packet!")
			ip4, _ := layer.(*layers.IPv4)
			fmt.Println(ip4)
			continue
		}

		if layer := eth.Layer(layers.LayerTypeARP); layer != nil {
			fmt.Println("This is a ARP packet!")
			arp, _ := layer.(*layers.ARP)
			fmt.Println(arp)
			continue
		}

		if layer := eth.Layer(layers.LayerTypeICMPv4); layer != nil {
			fmt.Println("This is a ICMPv4 packet!")
			icm, _ := layer.(*layers.ICMPv4)
			fmt.Println(icm)
			continue
		}

		if layer := eth.Layer(layers.LayerTypeDHCPv4); layer != nil {
			fmt.Println("This is a DHCPv4 packet!")
			dhc, _ := layer.(*layers.DHCPv4)
			fmt.Println(dhc)
			continue
		}

		if layer := eth.Layer(layers.LayerTypeTCP); layer != nil {
			fmt.Println("This is a TCP packet!")
			tcp, _ := layer.(*layers.TCP)
			fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
			continue
		}

		if layer := eth.Layer(layers.LayerTypeUDP); layer != nil {
			fmt.Println("This is a UDP packet!")
			udp, _ := layer.(*layers.UDP)
			fmt.Printf("From src port %d to dst port %d\n", udp.SrcPort, udp.DstPort)
			continue
		}

		/*
			for i, layer := range eth.Layers() {
				fmt.Println("PACKET LAYER:", layer.LayerType())
				fmt.Println(eth)
			}


				tcp := gopacket.NewPacket(buf[:n], layers.LayerTypeTCP, gopacket.Default)
				for i, layer := range tcp.Layers() {
					fmt.Println("PACKET LAYER:", i, layer.LayerType())
					fmt.Println(string(eth.Data()))
				}

				ip6 := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv6, gopacket.Default)
				for i, layer := range ip6.Layers() {
					fmt.Println("PACKET LAYER:", i, layer.LayerType())
					fmt.Println(string(eth.Data()))
				}

				for i := 0; i < n; i += 16 {
					p := i + 16
					if p < n {
						p = n
					}
					log.Println(buf[i:p])
					log.Println(string(buf[i:p]))
				}
		*/
	}
}
