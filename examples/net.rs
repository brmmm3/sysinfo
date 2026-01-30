// Take a look at the license at the top of the repository in the LICENSE file.

#[cfg(all(
    feature = "system",
    not(feature = "unknown-ci"),
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "windows",
    )
))]
use sysinfo::{get_default_network_interface, get_network_interfaces};

fn main() {
    #[cfg(all(
        feature = "system",
        not(feature = "unknown-ci"),
        any(
            target_os = "macos",
            target_os = "ios",
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "windows",
        )
    ))]
    {
        println!("All Interfaces:\n{:#?}", get_network_interfaces());
        println!("Default:\n{:#?}", get_default_network_interface());
    }
}
