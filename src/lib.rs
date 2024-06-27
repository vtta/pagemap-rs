//! A crate to provide a simple API to Linux kernel's
//! [pagemap API](https://www.kernel.org/doc/Documentation/vm/pagemap.txt).

#![feature(async_closure)]
#![doc(html_root_url = "https://docs.rs/pagemap/0.1.0")]
#![warn(rust_2018_idioms)]
#![deny(
    //missing_docs,
    unreachable_pub,
    broken_intra_doc_links,
)]

mod error;
#[macro_use]
mod kpage;
mod maps;
mod pagemap;

pub use crate::{
    error::{PageMapError, Result},
    kpage::KPageFlags,
    maps::{DeviceNumbers, MapsEntry, PagePermissions, VirtualMemoryArea},
    pagemap::{PageMap, PageMapEntry},
};

/// Retrieve system's page size in bytes.
pub fn page_size() -> Result<u64> {
    match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        -1 => Err(std::io::Error::last_os_error().into()),
        sz => Ok(sz as u64),
    }
}

/// Convenience function for [`PageMap::maps`], to parse all entries of `/proc/PID/maps` for the
/// process with the given `PID`.
#[inline]
pub async fn maps(pid: u64) -> Result<Vec<MapsEntry>> {
    PageMap::new(pid).await?.maps().await
}

/// Convenience wrapper for [`PageMap::pagemap`], to retrieve the entries of `/proc/PID/maps` for
/// the process with the given `PID`, combined with those in `/proc/PID/pagemap` (and also
/// `/proc/kpagecount` and `/proc/kpageflags`, if permitted).
#[inline]
pub async fn pagemap(pid: u64) -> Result<Vec<(MapsEntry, Vec<PageMapEntry>)>> {
    PageMap::new(pid).await?.pagemap().await
}

/// Calculate the "unique set size" (USS) (i.e., the amount of memory that a process is using
/// which is not shared with any other process) in bytes.
pub async fn uss(pid: u64) -> Result<u64> {
    Ok(PageMap::new(pid)
        .await?
        .pagemap()
        .await?
        .iter()
        .map(|(_, pmes)| {
            pmes.iter()
                .filter(|&pme| pme.present() && matches!(pme.kpagecount(), Some(c) if c == 1))
                .count() as u64
        })
        .sum::<u64>()
        * page_size()?)
}
