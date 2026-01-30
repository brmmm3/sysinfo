// Take a look at the license at the top of the repository in the LICENSE file.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::{self, NonNull, null_mut};

use winapi::shared::netioapi::ConvertLengthToIpv4Mask;
use winapi::shared::{ws2def, ws2ipdef};
use winapi::um::iphlpapi;
use winapi::um::iptypes::{GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
};

use crate::common::network::NetworkInterface;
use crate::{IpNetwork, MacAddr, SysInfoError};

/// this iterator yields an interface name and address
pub(crate) struct InterfaceAddressIterator {
    /// The first item in the linked list
    buf: *mut IP_ADAPTER_ADDRESSES_LH,
    /// The current adapter
    adapter: *mut IP_ADAPTER_ADDRESSES_LH,
}

impl InterfaceAddressIterator {
    fn new() -> Self {
        Self {
            buf: null_mut(),
            adapter: null_mut(),
        }
    }
    unsafe fn realloc(mut self, size: libc::size_t) -> Result<Self, String> {
        let new_buf = unsafe { libc::realloc(self.buf as _, size) as *mut IP_ADAPTER_ADDRESSES_LH };
        if new_buf.is_null() {
            // insufficient memory available
            // https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/malloc?view=msvc-170#return-value
            // malloc is not documented to set the last-error code
            Err("failed to allocate memory for IP_ADAPTER_ADDRESSES".to_string())
        } else {
            self.buf = new_buf;
            self.adapter = new_buf;
            Ok(self)
        }
    }
}

impl Iterator for InterfaceAddressIterator {
    type Item = (String, MacAddr);

    fn next(&mut self) -> Option<Self::Item> {
        if self.adapter.is_null() {
            return None;
        }
        unsafe {
            let adapter = self.adapter;
            // Move to the next adapter
            self.adapter = (*adapter).Next;
            if let Ok(interface_name) = (*adapter).FriendlyName.to_string() {
                // take the first 6 bytes and return the MAC address instead
                let [mac @ .., _, _] = (*adapter).PhysicalAddress;
                Some((interface_name, MacAddr(mac)))
            } else {
                // Not sure whether error can occur when parsing adapter name.
                self.next()
            }
        }
    }
}

impl InterfaceAddressIterator {
    pub fn generate_ip_networks(&mut self) -> HashMap<String, HashSet<IpNetwork>> {
        let mut results = HashMap::new();
        while !self.adapter.is_null() {
            unsafe {
                let adapter = self.adapter;
                // Move to the next adapter
                self.adapter = (*adapter).Next;
                if let Ok(interface_name) = (*adapter).FriendlyName.to_string() {
                    let ip_networks = get_ip_networks((*adapter).FirstUnicastAddress);
                    results.insert(interface_name, ip_networks);
                }
            }
        }
        results
    }
}

pub(crate) unsafe fn get_interface_ip_networks() -> HashMap<String, HashSet<IpNetwork>> {
    match unsafe { get_interface_address() } {
        Ok(mut interface_iter) => interface_iter.generate_ip_networks(),
        _ => HashMap::new(),
    }
}

impl Drop for InterfaceAddressIterator {
    fn drop(&mut self) {
        unsafe {
            libc::free(self.buf as _);
        }
    }
}

pub(crate) unsafe fn get_interface_address() -> Result<InterfaceAddressIterator, String> {
    // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses#remarks
    // A 15k buffer is recommended
    let mut size: u32 = 15 * 1024;
    let mut ret = ERROR_SUCCESS.0;
    let mut iterator = InterfaceAddressIterator::new();

    // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses#examples
    // Try to retrieve adapter information up to 3 times
    for _ in 0..3 {
        unsafe {
            iterator = iterator.realloc(size as _)?;
            ret = GetAdaptersAddresses(
                AF_UNSPEC.0.into(),
                GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER,
                None,
                Some(iterator.buf),
                &mut size,
            );
            if ret == ERROR_SUCCESS.0 {
                return Ok(iterator);
            } else if ret != ERROR_BUFFER_OVERFLOW.0 {
                break;
            }
        }
        // if the given memory size is too small to hold the adapter information,
        // the SizePointer returned will point to the required size of the buffer,
        // and we should continue.
        // Otherwise, break the loop and check the return code again
    }

    Err(format!("GetAdaptersAddresses() failed with code {ret}"))
}

fn get_ip_networks(mut prefixes_ptr: *mut IP_ADAPTER_UNICAST_ADDRESS_LH) -> HashSet<IpNetwork> {
    let mut ip_networks = HashSet::new();
    while !prefixes_ptr.is_null() {
        let prefix = unsafe { prefixes_ptr.read_unaligned() };
        if let Some(socket_address) = NonNull::new(prefix.Address.lpSockaddr)
            && let Some(ipaddr) = get_ip_address_from_socket_address(socket_address)
        {
            ip_networks.insert(IpNetwork {
                addr: ipaddr,
                prefix: prefix.OnLinkPrefixLength,
            });
        }
        prefixes_ptr = prefix.Next;
    }
    ip_networks
}

/// Converts a Windows socket address to an ip address.
fn get_ip_address_from_socket_address(socket_address: NonNull<SOCKADDR>) -> Option<IpAddr> {
    let socket_address_family = unsafe { socket_address.as_ref().sa_family };
    match socket_address_family {
        AF_INET => {
            let socket_address = unsafe { socket_address.cast::<SOCKADDR_IN>().as_ref() };
            let address = unsafe { socket_address.sin_addr.S_un.S_addr };
            let ipv4_address = IpAddr::from(address.to_ne_bytes());
            Some(ipv4_address)
        }
        AF_INET6 => {
            let socket_address = unsafe { socket_address.cast::<SOCKADDR_IN6>().as_ref() };
            let address = unsafe { socket_address.sin6_addr.u.Byte };
            let ipv6_address = IpAddr::from(address);
            Some(ipv6_address)
        }
        _ => None,
    }
}

/// Get all IP and MAC addresses for the network interfaces.
pub fn get_network_interfaces() -> Result<HashMap<String, NetworkInterface>, SysInfoError> {
    // Buffer for GetAdaptersAddresses
    let mut buffer_size: u32 = 0;
    let family = 0; // AF_UNSPEC (IPv4 and IPv6)
    let flags = GAA_FLAG_INCLUDE_GATEWAYS;

    // First call to get required buffer size
    unsafe {
        iphlpapi::GetAdaptersAddresses(
            family,
            flags,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut buffer_size,
        );
    }

    // Allocate buffer and call GetAdaptersAddresses
    let mut adapters_buffer = vec![0u8; buffer_size as usize];
    let adapters_ptr = adapters_buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES;
    let result = unsafe {
        iphlpapi::GetAdaptersAddresses(
            family,
            flags,
            ptr::null_mut(),
            adapters_ptr,
            &mut buffer_size,
        )
    };
    if result != 0 {
        return Err(SysInfoError::Io {
            kind: "GetAdaptersAddresses".to_string(),
            message: format!("failed with error: {result}"),
        });
    }

    // Get the best interface index for destination IP
    // Destination IP is 0.0.0.0 (default route)
    let dest_ip = u32::from(Ipv4Addr::new(0, 0, 0, 0)).to_be(); // network byte order
    let mut if_index = 0u32;
    let result = unsafe { iphlpapi::GetBestInterface(dest_ip, &mut if_index) };
    if result != 0 {
        return Err(SysInfoError::Io {
            kind: "GetBestInterface".to_string(),
            message: format!("failed with error: {result}"),
        });
    }

    // Iterate through adapters
    let mut interfaces = HashMap::new();

    let mut adapter = adapters_ptr;
    while !adapter.is_null() {
        let adapter_ref = unsafe { &*adapter };

        // Get gateway address
        let mut gateway = None;
        let mut gateway_ptr = adapter_ref.FirstGatewayAddress;
        while !gateway_ptr.is_null() && gateway.is_none() {
            let gateway_ref = unsafe { &*gateway_ptr };
            gateway = sockaddr_to_ipaddr(gateway_ref.Address.lpSockaddr);
            gateway_ptr = gateway_ref.Next;
        }

        // Iterate through unicast addresses
        let mut unicast_addr = adapter_ref.FirstUnicastAddress;
        while !unicast_addr.is_null() {
            let unicast_ref = unsafe { &*unicast_addr };
            let sockaddr_ptr = unicast_ref.Address.lpSockaddr;
            let mut broadcast = None;

            // Convert prefix length to netmask
            let unicast = unsafe { &*unicast_addr };
            let prefix_length = unicast.OnLinkPrefixLength;
            let mut netmask_u32: u32 = 0;
            let result = unsafe { ConvertLengthToIpv4Mask(prefix_length as u32, &mut netmask_u32) };
            let netmask = if result == 0 && netmask_u32 != 0 {
                Some(IpAddr::V4(Ipv4Addr::from(netmask_u32)))
            } else {
                None
            };

            // Extract IP address
            let ip = match unsafe { (*sockaddr_ptr).sa_family as i32 } {
                ws2def::AF_INET => {
                    let sockaddr_in = unsafe { &*(sockaddr_ptr as *const ws2def::SOCKADDR_IN) };
                    let ip_addr = unsafe { *sockaddr_in.sin_addr.S_un.S_addr() };
                    broadcast = Some(IpAddr::V4(Ipv4Addr::from(
                        u32::from_be(ip_addr) & !netmask_u32,
                    )));
                    let ipv4 = Ipv4Addr::from(u32::from_be(ip_addr));
                    IpAddr::V4(ipv4)
                }
                ws2def::AF_INET6 => {
                    let sockaddr_in6 = unsafe { &*(sockaddr_ptr as *const ws2ipdef::SOCKADDR_IN6) };
                    let ipv6 = unsafe { sockaddr_in6.sin6_addr.u.Byte() };
                    IpAddr::V6(std::net::Ipv6Addr::from(*ipv6))
                }
                _ => continue,
            };

            // Get MAC address
            let mac = if adapter_ref.PhysicalAddressLength >= 6 {
                MacAddr(adapter_ref.PhysicalAddress[..6].try_into().unwrap())
            } else {
                MacAddr([0; 6])
            };

            let name = wide_ptr_to_string(adapter_ref.FriendlyName);
            let domain = wide_ptr_to_string(adapter_ref.DnsSuffix);
            interfaces.insert(
                name.clone(),
                NetworkInterface {
                    name,
                    mac,
                    ip,
                    netmask,
                    broadcast,
                    gateway,
                    domain: if domain.is_empty() {
                        None
                    } else {
                        Some(domain)
                    },
                    is_default: (adapter_ref).Ipv6IfIndex == if_index,
                },
            );

            unicast_addr = unicast_ref.Next;
        }
        adapter = adapter_ref.Next;
    }
    Ok(interfaces)
}

/// Get defaul IP and MAC address
pub fn get_default_network_interface() -> Result<Option<NetworkInterface>, SysInfoError> {
    for interface in get_network_interfaces()?.into_values() {
        if interface.is_default {
            return Ok(Some(interface));
        }
    }
    Ok(None)
}

/// Converts a Windows wide string pointer to a Rust String.
fn wide_ptr_to_string(ptr: *mut u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        // Find the length of the null-terminated wide string
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

fn sockaddr_to_ipaddr(sockaddr: *const ws2def::SOCKADDR) -> Option<IpAddr> {
    if sockaddr.is_null() {
        return None;
    }

    let sockaddr_ref = unsafe { &*sockaddr };
    match sockaddr_ref.sa_family as i32 {
        ws2def::AF_INET => {
            let sockaddr_in = unsafe { *(sockaddr as *const ws2def::SOCKADDR_IN) };
            let ipv4 = unsafe { Ipv4Addr::from(u32::from_be(*sockaddr_in.sin_addr.S_un.S_addr())) };
            Some(IpAddr::V4(ipv4))
        }
        ws2def::AF_INET6 => {
            let sockaddr_in6 = unsafe { *(sockaddr as *const ws2ipdef::SOCKADDR_IN6) };
            let ipv6 = unsafe { sockaddr_in6.sin6_addr.u.Byte() };
            Some(IpAddr::V6(Ipv6Addr::from(*ipv6)))
        }
        _ => None,
    }
}
