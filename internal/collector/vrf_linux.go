//go:build linux

package collector

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Linux netlink attribute types used for link kind detection.
// IFLA_LINKINFO (18) carries a nested attribute set; within it,
// IFLA_INFO_KIND (1) is the null-terminated kind string (e.g. "vrf", "bridge").
const (
	iflaLinkinfo uint16 = 18
	iflaInfoKind uint16 = 1
)

// Sizes of the two fixed netlink structs we need to build the RTM_GETLINK request.
const (
	nlMsgHdrSize  = 16 // sizeof(NlMsghdr)
	ifInfomsgSize = 16 // sizeof(IfInfomsg)
)

// networkInfo holds precomputed mappings for interface and VRF resolution.
type networkInfo struct {
	addrToIface map[string]string // IP address → interface name
	ifaceToVRF  map[string]string // interface name → VRF name
}

// buildNetworkInfo constructs address→interface and interface→VRF mappings by
// reading the system's network interfaces and querying the kernel for VRF info.
func buildNetworkInfo() networkInfo {
	info := networkInfo{
		addrToIface: make(map[string]string),
		ifaceToVRF:  make(map[string]string),
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return info
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				info.addrToIface[ip.String()] = iface.Name
			}
		}

		if vrf := resolveVRF(iface.Name); vrf != "" {
			info.ifaceToVRF[iface.Name] = vrf
		}
	}

	return info
}

// resolveVRF returns the VRF name for the given interface, or an empty string
// if the interface is not part of a VRF. It reads /sys/class/net/<iface>/master
// to find the master device, then confirms via netlink that the master is a VRF.
func resolveVRF(ifaceName string) string {
	masterLink := filepath.Join("/sys/class/net", ifaceName, "master")
	target, err := os.Readlink(masterLink)
	if err != nil {
		return ""
	}

	masterName := filepath.Base(target)
	master, err := net.InterfaceByName(masterName)
	if err != nil {
		return ""
	}

	if getLinkKind(master.Index) == "vrf" {
		return masterName
	}
	return ""
}

// getLinkKind sends a netlink RTM_GETLINK request and returns the link kind
// string (e.g. "vrf", "bridge", "bond") for the interface with the given index.
// Returns an empty string on any error or if the kind attribute is absent.
func getLinkKind(ifIndex int) string {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return ""
	}
	defer syscall.Close(fd)

	// Build the RTM_GETLINK request: NlMsghdr followed by IfInfomsg.
	//
	// NlMsghdr layout (16 bytes):
	//   [0:4]  Len   uint32
	//   [4:6]  Type  uint16  ← RTM_GETLINK
	//   [6:8]  Flags uint16  ← NLM_F_REQUEST
	//   [8:12] Seq   uint32
	//   [12:16] Pid  uint32
	//
	// IfInfomsg layout (16 bytes):
	//   [0]    Family uint8   ← AF_UNSPEC
	//   [1]    Pad    uint8
	//   [2:4]  Type   uint16
	//   [4:8]  Index  int32   ← interface index
	//   [8:12] Flags  uint32
	//   [12:16] Change uint32
	const reqLen = nlMsgHdrSize + ifInfomsgSize
	buf := make([]byte, reqLen)

	binary.NativeEndian.PutUint32(buf[0:4], uint32(reqLen))
	binary.NativeEndian.PutUint16(buf[4:6], syscall.RTM_GETLINK)
	binary.NativeEndian.PutUint16(buf[6:8], syscall.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(buf[8:12], 1)  // seq
	binary.NativeEndian.PutUint32(buf[12:16], 0) // pid

	buf[16] = syscall.AF_UNSPEC // IfInfomsg.Family
	binary.NativeEndian.PutUint32(buf[20:24], uint32(ifIndex)) // IfInfomsg.Index

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Sendto(fd, buf, 0, sa); err != nil {
		return ""
	}

	resp := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, resp, 0)
	if err != nil || n < nlMsgHdrSize {
		return ""
	}

	msgs, err := syscall.ParseNetlinkMessage(resp[:n])
	if err != nil {
		return ""
	}

	for _, msg := range msgs {
		if msg.Header.Type != syscall.RTM_NEWLINK {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&msg)
		if err != nil {
			continue
		}
		for _, attr := range attrs {
			// Mask off NLA_F_NESTED (bit 15) before comparing the type.
			if attr.Attr.Type&0x7fff == iflaLinkinfo {
				return parseInfoKind(attr.Value)
			}
		}
	}
	return ""
}

// parseInfoKind extracts IFLA_INFO_KIND from the raw bytes of an IFLA_LINKINFO
// netlink attribute value. The kind is a null-terminated ASCII string.
func parseInfoKind(data []byte) string {
	for len(data) >= 4 {
		attrLen := binary.NativeEndian.Uint16(data[0:2])
		attrType := binary.NativeEndian.Uint16(data[2:4]) & 0x7fff
		if attrLen < 4 || int(attrLen) > len(data) {
			break
		}
		if attrType == iflaInfoKind {
			return strings.TrimRight(string(data[4:attrLen]), "\x00")
		}
		// Netlink attributes are 4-byte aligned.
		next := (int(attrLen) + 3) &^ 3
		if next >= len(data) {
			break
		}
		data = data[next:]
	}
	return ""
}

// lookupInterface returns the interface name for the given IP address.
// Falls back to guessNetworkInterface when the address is not in the map.
func (n *networkInfo) lookupInterface(addr string) string {
	if iface, ok := n.addrToIface[addr]; ok {
		return iface
	}
	return guessNetworkInterface(addr)
}

// lookupVRF returns the VRF name for the given interface, or an empty string.
func (n *networkInfo) lookupVRF(ifaceName string) string {
	return n.ifaceToVRF[ifaceName]
}
