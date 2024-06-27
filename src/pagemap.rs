use async_std::{
    fs::File,
    io::{prelude::*, BufReader, SeekFrom},
    stream,
};
use futures::stream::{StreamExt, TryStreamExt};
use std::iter::Iterator;
use std::{fmt, iter};

use crate::{
    error::{PageMapError, Result},
    kpage::KPageFlags,
    maps::{MapsEntry, VirtualMemoryArea},
    page_size,
};

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// PageMapEntry
//
///////////////////////////////////////////////////////////////////////////////////////////////////

/// An entry read from `/proc/<PID>/pagemap` for a process, and optionally from `/proc/kpagecount`
/// and `/proc/kpageflags` too.
///
/// Documentation and details about the various bits of the API can be found in Linux, at
/// [`doc/Documentation/vm/pagemap.txt`](https://www.kernel.org/doc/Documentation/vm/pagemap.txt).
#[derive(Debug, Clone, Copy, Default)]
pub struct PageMapEntry {
    pgmap: u64,
    kpgcn: Option<u64>,
    kpgfl: Option<KPageFlags>,
}

impl std::convert::From<u64> for PageMapEntry {
    fn from(pgmap: u64) -> Self {
        PageMapEntry {
            pgmap,
            kpgcn: None,
            kpgfl: None,
        }
    }
}

// TODO: Where to use?
impl std::convert::From<(u64, u64, u64)> for PageMapEntry {
    fn from((pgmap, kpgcn, kpgfl): (u64, u64, u64)) -> Self {
        PageMapEntry {
            pgmap,
            kpgcn: Some(kpgcn),
            kpgfl: Some(kpgfl.into()),
        }
    }
}

/// Constants are defined in Linux, at `fs/proc/task_mmu.c`.
impl PageMapEntry {
    ///////////////////////////////////////////////////////////////////////////////////////////
    // pagemap constants as defined in Linux, at `fs/proc/task_mmu.c`
    ///////////////////////////////////////////////////////////////////////////////////////////

    pub const PM_PFRAME_BITS: u64 = 55;
    pub const PM_PFRAME_MASK: u64 = (1 << Self::PM_PFRAME_BITS) - 1;
    pub const PM_SOFT_DIRTY: u64 = 55;
    pub const PM_MMAP_EXCLUSIVE: u64 = 56;
    pub const PM_FILE: u64 = 61;
    pub const PM_SWAP: u64 = 62;
    pub const PM_PRESENT: u64 = 63;

    ///////////////////////////////////////////////////////////////////////////////////////////
    // /proc/PID/pagemap
    ///////////////////////////////////////////////////////////////////////////////////////////

    /// The raw `u64` value as read from [`procfs(5)`].
    ///
    /// [`procfs(5)`]: https://man7.org/linux/man-pages/man5/proc.5.html
    #[inline(always)]
    pub fn raw_pagemap(&self) -> u64 {
        self.pgmap
    }

    /// Returns `true` if the [`Self::PM_PRESENT`] bit is set; `false` otherwise.
    #[inline(always)]
    pub fn present(&self) -> bool {
        self.pgmap >> Self::PM_PRESENT & 1 == 1
    }

    /// Returns `true` if the [`Self::PM_SWAP`] bit is set; `false` otherwise.
    #[inline(always)]
    pub fn swapped(&self) -> bool {
        self.pgmap >> Self::PM_SWAP & 1 == 1
    }

    /// Returns `true` if the [`Self::PM_FILE`] bit is set; `false` otherwise.
    #[inline(always)]
    pub fn file_mapped(&self) -> bool {
        self.pgmap >> Self::PM_FILE & 1 == 1
    }

    /// Returns `true` if the [`Self::PM_FILE`] bit is clear; `false` otherwise.
    #[inline(always)]
    pub fn shared_anonymous(&self) -> bool {
        self.pgmap >> Self::PM_FILE & 1 == 0
    }

    /// Returns `true` if the [`Self::PM_MMAP_EXCLUSIVE`] bit is set; `false` otherwise.
    #[inline(always)]
    pub fn exclusively_mapped(&self) -> bool {
        self.pgmap >> Self::PM_MMAP_EXCLUSIVE & 1 == 1
    }

    /// Returns `true` if the [`Self::PM_SOFT_DIRTY`] bit is set; `false` otherwise.
    #[inline(always)]
    pub fn soft_dirty(&self) -> bool {
        self.pgmap >> Self::PM_SOFT_DIRTY & 1 == 1
    }

    /// Returns the page frame number (decoding bits 0-54) if the [`Self::PM_PRESENT`] bit is set;
    /// otherwise returns an error.
    pub fn pfn(&self) -> Result<u64> {
        if !self.present() {
            Err(PageMapError::PageNotPresent)
        } else {
            Ok(self.pgmap & Self::PM_PFRAME_MASK)
        }
    }

    /// Returns the swap type (decoding bits 0-4) if the [`Self::PM_SWAP`] bit is set; otherwise
    /// returns an error.
    pub fn swap_type(&self) -> Result<u8> {
        if !self.swapped() {
            Err(PageMapError::PageNotSwapped)
        } else {
            Ok((self.pgmap & 0x1fu64) as u8)
        }
    }

    /// Returns the swap offset (decoding bits 5-55) if the [`Self::PM_SWAP`] bit is set; otherwise
    /// returns an error.
    pub fn swap_offset(&self) -> Result<u64> {
        if !self.swapped() {
            Err(PageMapError::PageNotSwapped)
        } else {
            Ok((self.pgmap & (0x_007f_ffff_ffff_ffe0_u64)) >> 5)
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // /proc/kpagecount
    ///////////////////////////////////////////////////////////////////////////////////////////

    /// The raw `u64` value as read from [`procfs(5)`], or `None` if `/proc/kpagecount` could not
    /// be accessed.
    ///
    /// [`procfs(5)`]: https://man7.org/linux/man-pages/man5/proc.5.html
    #[inline(always)]
    pub fn kpagecount(&self) -> Option<u64> {
        self.kpgcn
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // /proc/kpageflags
    ///////////////////////////////////////////////////////////////////////////////////////////

    /// The [`KPageFlags`] parsed from `/proc/kpageflags` for the page frame in this
    /// `PageMapEntry`.
    #[inline(always)]
    pub fn kpageflags(&self) -> Option<KPageFlags> {
        self.kpgfl
    }

    /// The raw `u64` value as read from [`procfs(5)`], or `None` if `/proc/kpageflags` could not
    /// be accessed.
    ///
    /// [`procfs(5)`]: https://man7.org/linux/man-pages/man5/proc.5.html
    #[inline(always)]
    pub fn raw_kpageflags(&self) -> Option<u64> {
        self.kpgfl.map(|kpgfl| kpgfl.bits())
    }

    fn_get_bit!(locked, KPF_LOCKED);
    fn_get_bit!(error, KPF_ERROR);
    fn_get_bit!(referenced, KPF_REFERENCED);
    fn_get_bit!(uptodate, KPF_UPTODATE);
    fn_get_bit!(dirty, KPF_DIRTY);
    fn_get_bit!(lru, KPF_LRU);
    fn_get_bit!(active, KPF_ACTIVE);
    fn_get_bit!(slab, KPF_SLAB);
    fn_get_bit!(writeback, KPF_WRITEBACK);
    fn_get_bit!(reclaim, KPF_RECLAIM);
    fn_get_bit!(buddy, KPF_BUDDY);
    fn_get_bit!(mmap, KPF_MMAP);
    fn_get_bit!(anon, KPF_ANON);
    fn_get_bit!(swapcache, KPF_SWAPCACHE);
    fn_get_bit!(swapbacked, KPF_SWAPBACKED);
    fn_get_bit!(compound_head, KPF_COMPOUND_HEAD);
    fn_get_bit!(compound_tail, KPF_COMPOUND_TAIL);
    fn_get_bit!(huge, KPF_HUGE);
    fn_get_bit!(unevictable, KPF_UNEVICTABLE);
    fn_get_bit!(hwpoison, KPF_HWPOISON);
    fn_get_bit!(nopage, KPF_NOPAGE);
    fn_get_bit!(ksm, KPF_KSM);
    fn_get_bit!(thp, KPF_THP);
    fn_get_bit!(offline, KPF_OFFLINE);
    fn_get_bit!(zero_page, KPF_ZERO_PAGE);
    fn_get_bit!(idle, KPF_IDLE);
    fn_get_bit!(pgtable, KPF_PGTABLE);
}

impl fmt::Display for PageMapEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.present(), self.swapped()) {
            (true, true) => unreachable!("PAGE BOTH PRESENT AND SWAPPED!"),
            (true, false) => {
                write!(
                    f,
                    "PageMapEntry{{ present: {}; swapped: {}; file_mapped: {}; exclusively_mapped: {}; soft_dirty: {}; pfn: 0x{:x} }}",
                    self.present(), self.swapped(), self.file_mapped(), self.exclusively_mapped(),
                    self.soft_dirty(), self.pfn().unwrap(), // Safe because self.present() == true
                )
            }
            (false, true) => {
                write!(
                    f,
                    "PageMapEntry{{ present: {}; swapped: {}; file_mapped: {}; exclusively_mapped: {}; soft_dirty: {}; swap_type: {}; swap_offset: 0x{:x} }}",
                    self.present(), self.swapped(), self.file_mapped(), self.exclusively_mapped(),
                    self.soft_dirty(), self.swap_type().unwrap(), self.swap_offset().unwrap(),
                    // Safe to unwrap because self.swapped() == true
                )
            }
            (false, false) => {
                write!(
                    f,
                    "PageMapEntry{{ present: {}; swapped: {}; file_mapped: {}; exclusively_mapped: {}; soft_dirty: {} }}",
                    self.present(), self.swapped(), self.file_mapped(), self.exclusively_mapped(),
                    self.soft_dirty(),
                )
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//
// PageMap
//
///////////////////////////////////////////////////////////////////////////////////////////////////

/// A handle used to read from:
///
/// - `/proc/<PID>/maps`,
/// - `/proc/<PID>/pagemap`,
/// - `/proc/kpagecount`, and
/// - `/proc/kpageflags`
///
/// for a specific process.
#[derive(Debug)]
pub struct PageMap {
    pid: u64,
    mf: BufReader<File>,
    pmf: File,
    kcf: Option<File>,
    kff: Option<File>,
    page_size: u64,
}

impl PageMap {
    const KPAGECOUNT: &'static str = "/proc/kpagecount";
    const KPAGEFLAGS: &'static str = "/proc/kpageflags";

    /// Construct a new `PageMap` for the process with the given `PID`.
    pub async fn new(pid: u64) -> Result<Self> {
        let (kcf, kff) = (
            File::open(Self::KPAGECOUNT)
                .await
                .map_err(|e| PageMapError::Open {
                    path: Self::KPAGECOUNT.into(),
                    source: e,
                })
                .ok(),
            File::open(Self::KPAGEFLAGS)
                .await
                .map_err(|e| PageMapError::Open {
                    path: Self::KPAGEFLAGS.into(),
                    source: e,
                })
                .ok(),
        );
        let (maps_path, pagemap_path) = (
            format!("/proc/{}/maps", pid),
            format!("/proc/{}/pagemap", pid),
        );
        Ok(PageMap {
            pid,
            mf: BufReader::with_capacity(
                1 << 14,
                File::open(&maps_path)
                    .await
                    .map_err(|e| PageMapError::Open {
                        path: maps_path,
                        source: e,
                    })?,
            ),
            pmf: File::open(&pagemap_path)
                .await
                .map_err(|e| PageMapError::Open {
                    path: pagemap_path,
                    source: e,
                })?,
            kcf,
            kff,
            page_size: page_size()?,
        })
    }

    /// Returns the `PID` of the process that this `PageMap` concerns.
    pub fn pid(&self) -> u64 {
        self.pid
    }

    /// Returns all virtual memory mappings for the process at hand, as parsed from
    /// `/proc/<PID>/maps`.
    pub async fn maps(&mut self) -> Result<Vec<MapsEntry>> {
        let pid = self.pid;
        self.mf
            .by_ref()
            .lines()
            .map(|line| {
                line.map_err(|e| PageMapError::Read {
                    path: format!("/proc/{}/maps", pid),
                    source: e,
                })?
                .parse()
            })
            .try_collect()
            .await
    }

    /// Returns the entries parsed from reading `/proc/<PID>/pagemap` for all pages in the
    /// specified [`VirtualMemoryArea`] of the process at hand.

    async fn pagemap_vma_of(
        pid: u64,
        page_size: u64,
        pmf: File,
        vma: &VirtualMemoryArea,
    ) -> Result<Vec<PageMapEntry>> {
        let mut buf = [0; 8];
        let s = stream::from_iter(
            (vma.start..vma.end)
                .step_by(page_size as _)
                .zip(iter::repeat(pmf.clone())),
        )
        .then(|(addr, mut pmf)| async move {
            let vpn = addr / page_size;
            pmf.seek(SeekFrom::Start(vpn * 8))
                .await
                .map_err(|e| PageMapError::Seek {
                    path: format!("/proc/{}/pagemap", pid),
                    source: e,
                })?;
            pmf.read_exact(&mut buf)
                .await
                .map_err(|e| PageMapError::Read {
                    path: format!("/proc/{}/pagemap", pid),
                    source: e,
                })?;
            Ok(PageMapEntry::from(u64::from_ne_bytes(buf)))
        });
        s.try_collect().await
    }

    pub async fn pagemap_vma(&mut self, vma: &VirtualMemoryArea) -> Result<Vec<PageMapEntry>> {
        Self::pagemap_vma_of(self.pid, self.page_size, self.pmf.clone(), vma).await
    }

    /// Returns the information about memory mappings, as parsed from reading `/proc/<PID>/maps`,
    /// along with a `Vec<PageMapEntry>` for each of them, which represent the information read
    /// from `/proc/<PID>/pagemap` for each contiguous page in each virtual memory area.
    ///
    /// If permitted, every [`PageMapEntry`] is also populated with information read from
    /// `/proc/kpagecount` and `/proc/kpageflags`.
    pub async fn pagemap(&mut self) -> Result<Vec<(MapsEntry, Vec<PageMapEntry>)>> {
        let (pid, page_size, pmf) = (self.pid, self.page_size, self.pmf.clone());
        let kcf = self
            .kcf
            .clone()
            .ok_or_else(|| PageMapError::Access(Self::KPAGECOUNT.into()))?;
        let kff = self
            .kff
            .clone()
            .ok_or_else(|| PageMapError::Access(Self::KPAGEFLAGS.into()))?;
        stream::from_iter(
            self.maps()
                .await?
                .into_iter()
                .zip(iter::repeat((pmf, kcf, kff))),
        )
        .then(|(map_entry, (pmf, kcf, kff))| async move {
            let mut pmes = Self::pagemap_vma_of(pid, page_size, pmf, &map_entry.vma()).await?;
            for pme in &mut pmes {
                if let Ok(pfn) = pme.pfn() {
                    pme.kpgcn = Some(Self::kpagecount_of(kcf.clone(), pfn).await?);
                    pme.kpgfl = Some(Self::kpageflags_of(kff.clone(), pfn).await?);
                }
            }
            Ok((map_entry, pmes))
        })
        .try_collect()
        .await
    }

    async fn kpagecount_of(mut kcf: File, pfn: u64) -> Result<u64> {
        let mut buf = [0; 8];
        kcf.seek(SeekFrom::Start(pfn * 8))
            .await
            .map_err(|e| PageMapError::Seek {
                path: Self::KPAGECOUNT.into(),
                source: e,
            })?;
        kcf.read_exact(&mut buf)
            .await
            .map_err(|e| PageMapError::Read {
                path: Self::KPAGECOUNT.into(),
                source: e,
            })?;
        Ok(u64::from_ne_bytes(buf))
    }

    /// Attempt to read the number of times that the page with the given `PFN` is referenced, from
    /// `/proc/kpagecount`.
    ///
    /// # Errors
    ///
    /// The method may return [`PageMapError::Read`] or [`PageMapError::Seek`] if either reading
    /// from or seeking into `/proc/kpagecount` fails.
    ///
    /// Most importantly, the method may return [`PageMapError::Access`] if opening
    /// `/proc/kpagecount` was not permitted at the time that the `PageMapEntry` was instantiated.
    pub async fn kpagecount(&self, pfn: u64) -> Result<u64> {
        let kcf = self
            .kcf
            .clone()
            .ok_or_else(|| PageMapError::Access(Self::KPAGECOUNT.into()))?;
        Self::kpagecount_of(kcf, pfn).await
    }

    async fn kpageflags_of(mut kff: File, pfn: u64) -> Result<KPageFlags> {
        let mut buf = [0; 8];
        kff.seek(SeekFrom::Start(pfn * 8))
            .await
            .map_err(|e| PageMapError::Seek {
                path: Self::KPAGEFLAGS.into(),
                source: e,
            })?;
        kff.read_exact(&mut buf)
            .await
            .map_err(|e| PageMapError::Read {
                path: Self::KPAGEFLAGS.into(),
                source: e,
            })?;
        Ok(KPageFlags::from_bits_truncate(u64::from_ne_bytes(buf)))
    }

    /// Attempt to read the flags for the page with the given `PFN` from `/proc/kpageflags`.
    ///
    /// # Errors
    ///
    /// The method may return [`PageMapError::Read`] or [`PageMapError::Seek`] if either reading
    /// from or seeking into `/proc/kpageflags` fails.
    ///
    /// Most importantly, the method may return [`PageMapError::Access`] if opening
    /// `/proc/kpageflags` was not permitted at the time that the `PageMapEntry` was instantiated.
    pub async fn kpageflags(&self, pfn: u64) -> Result<KPageFlags> {
        let kff = self
            .kff
            .clone()
            .ok_or_else(|| PageMapError::Access(Self::KPAGEFLAGS.into()))?;
        Self::kpageflags_of(kff, pfn).await
    }
}
