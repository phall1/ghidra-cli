//! ELF loader for the Phase 3 Rust decompiler-host (E7.3).
//!
//! When the Rust host drives Ghidra's C++ `decompile` binary, the
//! decompiler streams callbacks back over its packed/attributed-XML
//! pipe. One of the most frequent is `command_getbytes` (see
//! `docs/decompiler-protocol.md` §4.2.13), which asks the host to
//! produce `N` bytes of program memory at a virtual address.
//!
//! That callback is exactly what this module answers. For now we
//! scope tightly to **x86_64 ELF** — the only target Phase 3 needs
//! to land. PE / Mach-O / 32-bit / other architectures will arrive
//! as follow-up issues once we have a working end-to-end vertical
//! slice.
//!
//! ## Design notes
//!
//! - We `std::fs::read` the entire file into a `Vec<u8>` rather than
//!   `mmap`-ing it. Decompiler `getbytes` callbacks are small
//!   (typically `len <= 16`) and infrequent at the timescale where
//!   mmap would matter; the file sizes we care about (single-binary
//!   reverse-engineering) fit comfortably in RAM. mmap would buy us
//!   nothing here and would add an `unsafe` dependency and a story
//!   for file-truncation-while-mapped.
//!
//! - BSS handling: a LOAD segment with `p_memsz > p_filesz` has a
//!   zero-initialized tail that is **not** on disk. Real loaders
//!   (`ld.so`, kernel) zero-fill that tail in memory. A decompiler
//!   asking for `.bss` bytes therefore expects zeros, not an error.
//!   This loader matches that behavior — see [`ElfLoader::read_bytes`].
//!
//! - Crossing a gap between segments is an **error**, not a silent
//!   splice. If the decompiler asks for bytes that straddle a hole
//!   in the address space we want the failure to be loud so we can
//!   diagnose it.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use goblin::Object;

/// Architecture variants this loader recognizes. Phase 3 only needs
/// x86_64 — additional variants will be added as the host grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    Amd64,
}

/// A loadable program segment, as the runtime loader would see it.
///
/// `memsz >= filesz`; the `[filesz, memsz)` tail is the zero-filled
/// BSS portion that does not exist on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Virtual address of the first byte of the segment.
    pub vaddr: u64,
    /// Number of bytes occupied in memory (includes BSS tail).
    pub memsz: u64,
    /// Number of bytes physically present in the file.
    pub filesz: u64,
    /// Offset of the file-backed portion within the on-disk image.
    pub file_offset: u64,
    /// PF_R / PF_W / PF_X permission bits, OR'd together.
    pub perms: u32,
}

impl Segment {
    /// True if the read permission bit is set.
    pub fn is_readable(&self) -> bool {
        self.perms & PF_R != 0
    }
    /// True if the write permission bit is set.
    pub fn is_writable(&self) -> bool {
        self.perms & PF_W != 0
    }
    /// True if the execute permission bit is set.
    pub fn is_executable(&self) -> bool {
        self.perms & PF_X != 0
    }
}

/// x86_64 ELF loader. Holds the on-disk image plus the parsed LOAD
/// segment table; serves `command_getbytes`-shaped queries via
/// [`ElfLoader::read_bytes`].
#[derive(Debug)]
pub struct ElfLoader {
    /// The full file bytes. See module docs for why this is a `Vec`
    /// and not an `Mmap`.
    image: Vec<u8>,
    /// Parsed PT_LOAD segments, in arbitrary order. We do not assume
    /// they are sorted by `vaddr`; lookups linear-scan, which is
    /// fine for the handful of segments a typical binary has.
    segments: Vec<Segment>,
    /// Virtual address of the program entry point, as recorded in
    /// the ELF header.
    entry: u64,
    /// Architecture detected from `e_machine`.
    arch: Architecture,
}

impl ElfLoader {
    /// Read an ELF file from disk and parse its program headers.
    ///
    /// Errors if the file is not an ELF, not x86_64, or unreadable.
    pub fn open(path: &Path) -> Result<Self> {
        let image = std::fs::read(path)
            .with_context(|| format!("reading ELF image from {}", path.display()))?;
        Self::from_bytes(image)
    }

    /// Same as [`open`](Self::open) but takes an already-loaded byte
    /// buffer. Useful for tests and for callers that already have
    /// the file contents in memory.
    pub fn from_bytes(image: Vec<u8>) -> Result<Self> {
        let object = Object::parse(&image).context("parsing object file via goblin")?;

        let elf = match object {
            Object::Elf(elf) => elf,
            Object::PE(_) => bail!("unsupported object format: PE (only ELF is supported)"),
            Object::Mach(_) => bail!("unsupported object format: Mach-O (only ELF is supported)"),
            Object::Archive(_) => {
                bail!("unsupported object format: archive (only ELF is supported)")
            }
            // `Object` is non-exhaustive in goblin; catch-all keeps
            // us forward-compatible.
            _ => bail!("unsupported object format (only ELF is supported)"),
        };

        // Only x86_64 for now — Phase 3's first vertical slice.
        let arch = match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => Architecture::Amd64,
            other => bail!(
                "unsupported ELF e_machine {:#x} (only x86_64 / EM_X86_64 = 0x3e is supported)",
                other
            ),
        };

        let mut segments = Vec::new();
        for ph in &elf.program_headers {
            if ph.p_type != PT_LOAD {
                continue;
            }
            // ELF spec: filesz must be <= memsz. Goblin doesn't
            // enforce this, so guard ourselves — a malformed binary
            // with filesz > memsz would otherwise produce nonsense.
            if ph.p_filesz > ph.p_memsz {
                bail!(
                    "malformed ELF: PT_LOAD segment at vaddr {:#x} has filesz ({}) > memsz ({})",
                    ph.p_vaddr,
                    ph.p_filesz,
                    ph.p_memsz
                );
            }
            segments.push(Segment {
                vaddr: ph.p_vaddr,
                memsz: ph.p_memsz,
                filesz: ph.p_filesz,
                file_offset: ph.p_offset,
                perms: ph.p_flags,
            });
        }

        let entry = elf.header.e_entry;
        // `elf` borrows from `image`; drop it before moving `image`
        // into the struct.
        drop(elf);

        Ok(Self {
            image,
            segments,
            entry,
            arch,
        })
    }

    /// Program entry point as recorded in the ELF header (e_entry).
    pub fn entry_point(&self) -> u64 {
        self.entry
    }

    /// All PT_LOAD segments in the order they appear in the program
    /// header table.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Architecture detected from the ELF header.
    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    /// Read `len` bytes starting at virtual address `vaddr`, the way
    /// a runtime loader would see them.
    ///
    /// - Bytes in the file-backed portion of a LOAD segment come from
    ///   the on-disk image.
    /// - Bytes in the BSS tail (`[filesz, memsz)` of a LOAD segment)
    ///   are returned as zeros.
    /// - The full requested range MUST be covered by a single LOAD
    ///   segment. Reads that straddle a gap between segments — or
    ///   that fall entirely outside any segment — error out.
    pub fn read_bytes(&self, vaddr: u64, len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        // u64 end with overflow check — defends against pathological
        // requests like `vaddr = u64::MAX, len = 4`.
        let end = vaddr
            .checked_add(len as u64)
            .ok_or_else(|| anyhow!("vaddr {:#x} + len {} overflows u64", vaddr, len))?;

        let seg = self
            .segments
            .iter()
            .find(|s| s.vaddr <= vaddr && end <= s.vaddr.saturating_add(s.memsz))
            .ok_or_else(|| {
                // Distinguish "totally unmapped" from "straddles a
                // gap" to make debugging the decompiler easier.
                let start_in = self
                    .segments
                    .iter()
                    .any(|s| s.vaddr <= vaddr && vaddr < s.vaddr.saturating_add(s.memsz));
                let end_byte = end.saturating_sub(1);
                let end_in = self
                    .segments
                    .iter()
                    .any(|s| s.vaddr <= end_byte && end_byte < s.vaddr.saturating_add(s.memsz));
                if start_in && end_in {
                    anyhow!(
                        "read [{:#x}..{:#x}) straddles an unmapped gap between LOAD segments",
                        vaddr,
                        end
                    )
                } else if start_in {
                    anyhow!(
                        "read [{:#x}..{:#x}) starts inside a LOAD segment but extends past its end into unmapped memory",
                        vaddr,
                        end
                    )
                } else {
                    anyhow!(
                        "read [{:#x}..{:#x}) is not covered by any LOAD segment",
                        vaddr,
                        end
                    )
                }
            })?;

        // Offset of the requested range from the start of the segment.
        let off_in_seg = vaddr - seg.vaddr;
        let mut out = vec![0u8; len];

        // How many of the requested bytes are file-backed vs. BSS?
        if off_in_seg < seg.filesz {
            let file_bytes_available = seg.filesz - off_in_seg;
            let n_from_file = std::cmp::min(file_bytes_available, len as u64) as usize;
            let start = (seg.file_offset + off_in_seg) as usize;
            let end_file = start
                .checked_add(n_from_file)
                .ok_or_else(|| anyhow!("file offset arithmetic overflow"))?;
            if end_file > self.image.len() {
                bail!(
                    "segment claims file bytes [{}..{}) but image is only {} bytes",
                    start,
                    end_file,
                    self.image.len()
                );
            }
            out[..n_from_file].copy_from_slice(&self.image[start..end_file]);
            // Bytes from `n_from_file..len` stay as the zero fill we
            // initialized `out` with — that's the BSS tail.
        }
        // else: entire request is in BSS, `out` is already zeroed.

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Synthetic ELF construction --------------------------------
    //
    // Hand-building a minimal x86_64 ELF lets us assert exact byte-
    // level layout without depending on the test-fixture binary's
    // (compiler-version-dependent) section layout.

    const EI_NIDENT: usize = 16;
    const ELF_HEADER_SIZE: usize = 64;
    const PROGRAM_HEADER_SIZE: usize = 56;
    const ET_EXEC: u16 = 2;
    const EM_X86_64: u16 = 62;

    /// Description of one LOAD segment for [`build_elf`].
    struct SegSpec {
        vaddr: u64,
        memsz: u64,
        file_data: Vec<u8>,
        perms: u32,
    }

    /// Build a minimal x86_64 ELF in memory. The file layout is:
    ///
    /// ```text
    ///   [ELF header][program headers][segment 0 bytes][segment 1 bytes]...
    /// ```
    ///
    /// Returns `(image, segment_file_offsets)`.
    fn build_elf(entry: u64, segments: &[SegSpec]) -> (Vec<u8>, Vec<u64>) {
        let phdrs_offset = ELF_HEADER_SIZE;
        let phdrs_size = PROGRAM_HEADER_SIZE * segments.len();
        let mut cursor = (phdrs_offset + phdrs_size) as u64;

        let mut seg_offsets = Vec::with_capacity(segments.len());
        for s in segments {
            seg_offsets.push(cursor);
            cursor += s.file_data.len() as u64;
        }
        let total_size = cursor as usize;
        let mut image = vec![0u8; total_size];

        // ---- ELF header ----
        image[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        image[4] = 2; // EI_CLASS = ELFCLASS64
        image[5] = 1; // EI_DATA = ELFDATA2LSB
        image[6] = 1; // EI_VERSION
                      // remaining e_ident bytes stay zero
        let mut off = EI_NIDENT;
        // e_type
        image[off..off + 2].copy_from_slice(&ET_EXEC.to_le_bytes());
        off += 2;
        // e_machine
        image[off..off + 2].copy_from_slice(&EM_X86_64.to_le_bytes());
        off += 2;
        // e_version
        image[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
        off += 4;
        // e_entry
        image[off..off + 8].copy_from_slice(&entry.to_le_bytes());
        off += 8;
        // e_phoff
        image[off..off + 8].copy_from_slice(&(phdrs_offset as u64).to_le_bytes());
        off += 8;
        // e_shoff
        image[off..off + 8].copy_from_slice(&0u64.to_le_bytes());
        off += 8;
        // e_flags
        image[off..off + 4].copy_from_slice(&0u32.to_le_bytes());
        off += 4;
        // e_ehsize
        image[off..off + 2].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
        off += 2;
        // e_phentsize
        image[off..off + 2].copy_from_slice(&(PROGRAM_HEADER_SIZE as u16).to_le_bytes());
        off += 2;
        // e_phnum
        image[off..off + 2].copy_from_slice(&(segments.len() as u16).to_le_bytes());
        off += 2;
        // e_shentsize / e_shnum / e_shstrndx — all zero
        // (we have no section headers; goblin is happy with that)
        let _ = off;

        // ---- Program headers ----
        for (i, s) in segments.iter().enumerate() {
            let base = phdrs_offset + i * PROGRAM_HEADER_SIZE;
            // p_type
            image[base..base + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            // p_flags
            image[base + 4..base + 8].copy_from_slice(&s.perms.to_le_bytes());
            // p_offset
            image[base + 8..base + 16].copy_from_slice(&seg_offsets[i].to_le_bytes());
            // p_vaddr
            image[base + 16..base + 24].copy_from_slice(&s.vaddr.to_le_bytes());
            // p_paddr — same as vaddr, irrelevant for our purposes
            image[base + 24..base + 32].copy_from_slice(&s.vaddr.to_le_bytes());
            // p_filesz
            image[base + 32..base + 40]
                .copy_from_slice(&(s.file_data.len() as u64).to_le_bytes());
            // p_memsz
            image[base + 40..base + 48].copy_from_slice(&s.memsz.to_le_bytes());
            // p_align
            image[base + 48..base + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        }

        // ---- Segment bodies ----
        for (i, s) in segments.iter().enumerate() {
            let start = seg_offsets[i] as usize;
            image[start..start + s.file_data.len()].copy_from_slice(&s.file_data);
        }

        (image, seg_offsets)
    }

    #[test]
    fn rejects_non_elf_input() {
        let garbage = b"not an elf at all, just some bytes".to_vec();
        let err = ElfLoader::from_bytes(garbage).expect_err("should reject non-ELF");
        // goblin's own error surfaces through Context; we just need
        // *some* error, not silent success.
        let msg = format!("{err:#}");
        assert!(
            msg.to_lowercase().contains("pars")
                || msg.to_lowercase().contains("magic")
                || msg.to_lowercase().contains("elf"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn entry_point_matches_header() {
        let (image, _) = build_elf(
            0x40_1234,
            &[SegSpec {
                vaddr: 0x40_0000,
                memsz: 0x2000,
                file_data: vec![0xCC; 0x1000],
                perms: PF_R | PF_X,
            }],
        );
        let loader = ElfLoader::from_bytes(image).unwrap();
        assert_eq!(loader.entry_point(), 0x40_1234);
        assert_eq!(loader.architecture(), Architecture::Amd64);
        assert_eq!(loader.segments().len(), 1);
    }

    #[test]
    fn read_within_segment_returns_file_bytes() {
        // Distinctive content so we can verify the right slice.
        let body: Vec<u8> = (0..256u32).map(|b| b as u8).collect();
        let (image, _offsets) = build_elf(
            0x40_0000,
            &[SegSpec {
                vaddr: 0x40_0000,
                memsz: 0x100,
                file_data: body.clone(),
                perms: PF_R | PF_X,
            }],
        );
        let loader = ElfLoader::from_bytes(image).unwrap();

        // Read 16 bytes 32 bytes into the segment.
        let got = loader.read_bytes(0x40_0000 + 32, 16).unwrap();
        assert_eq!(got, body[32..48]);

        // Read from the very start.
        let got_head = loader.read_bytes(0x40_0000, 4).unwrap();
        assert_eq!(got_head, body[..4]);

        // Read the last in-file byte.
        let got_tail = loader.read_bytes(0x40_0000 + 0xFF, 1).unwrap();
        assert_eq!(got_tail, vec![body[0xFF]]);
    }

    #[test]
    fn read_in_bss_tail_returns_zeros() {
        // 0x100 bytes of file-backed content, 0x100 bytes of BSS
        // tail beyond it.
        let file_data = vec![0xAB; 0x100];
        let (image, _) = build_elf(
            0x40_0000,
            &[SegSpec {
                vaddr: 0x40_0000,
                memsz: 0x200,
                file_data,
                perms: PF_R | PF_W,
            }],
        );
        let loader = ElfLoader::from_bytes(image).unwrap();

        // Entirely in BSS.
        let bss = loader.read_bytes(0x40_0000 + 0x180, 16).unwrap();
        assert_eq!(bss, vec![0u8; 16]);

        // Straddle the filesz boundary: half file, half BSS.
        let straddle = loader.read_bytes(0x40_0000 + 0xF8, 16).unwrap();
        let mut expected = vec![0xAB; 8];
        expected.extend(std::iter::repeat_n(0u8, 8));
        assert_eq!(straddle, expected);
    }

    #[test]
    fn read_across_gap_errors() {
        // Two segments with a hole between them: [0x4000..0x5000) and
        // [0x6000..0x7000). Asking for bytes that cross 0x5000 should
        // fail loudly rather than silently splice.
        let (image, _) = build_elf(
            0x4000,
            &[
                SegSpec {
                    vaddr: 0x4000,
                    memsz: 0x1000,
                    file_data: vec![0x11; 0x1000],
                    perms: PF_R | PF_X,
                },
                SegSpec {
                    vaddr: 0x6000,
                    memsz: 0x1000,
                    file_data: vec![0x22; 0x1000],
                    perms: PF_R | PF_W,
                },
            ],
        );
        let loader = ElfLoader::from_bytes(image).unwrap();

        // Range [0x4FF8..0x5008): starts in seg 0, ends in unmapped gap.
        let err = loader.read_bytes(0x4FF8, 16).expect_err("must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unmapped") || msg.contains("not covered"),
            "expected gap-error message, got: {msg}"
        );
    }

    #[test]
    fn read_outside_any_segment_errors() {
        let (image, _) = build_elf(
            0x40_0000,
            &[SegSpec {
                vaddr: 0x40_0000,
                memsz: 0x1000,
                file_data: vec![0u8; 0x1000],
                perms: PF_R,
            }],
        );
        let loader = ElfLoader::from_bytes(image).unwrap();

        // Way below any segment.
        let err_low = loader.read_bytes(0x1000, 4).expect_err("must error");
        let msg_low = format!("{err_low:#}");
        assert!(
            msg_low.contains("not covered") || msg_low.contains("unmapped"),
            "got: {msg_low}"
        );

        // Way above any segment.
        let err_high = loader
            .read_bytes(0xFFFF_FFFF_0000_0000, 4)
            .expect_err("must error");
        let msg_high = format!("{err_high:#}");
        assert!(
            msg_high.contains("not covered") || msg_high.contains("unmapped"),
            "got: {msg_high}"
        );
    }

    #[test]
    fn zero_length_read_returns_empty() {
        let (image, _) = build_elf(
            0x40_0000,
            &[SegSpec {
                vaddr: 0x40_0000,
                memsz: 0x1000,
                file_data: vec![0u8; 0x1000],
                perms: PF_R,
            }],
        );
        let loader = ElfLoader::from_bytes(image).unwrap();
        assert!(loader.read_bytes(0x40_0000, 0).unwrap().is_empty());
        // Even a zero-length read at a totally bogus address is fine —
        // there's nothing to read, so there's nothing to fail on.
        assert!(loader.read_bytes(0xDEAD_BEEF, 0).unwrap().is_empty());
    }

    #[test]
    fn segment_perms_round_trip() {
        let (image, _) = build_elf(
            0x40_0000,
            &[
                SegSpec {
                    vaddr: 0x40_0000,
                    memsz: 0x1000,
                    file_data: vec![0u8; 0x1000],
                    perms: PF_R | PF_X,
                },
                SegSpec {
                    vaddr: 0x60_0000,
                    memsz: 0x1000,
                    file_data: vec![0u8; 0x1000],
                    perms: PF_R | PF_W,
                },
            ],
        );
        let loader = ElfLoader::from_bytes(image).unwrap();
        let segs = loader.segments();
        assert!(segs[0].is_readable() && segs[0].is_executable() && !segs[0].is_writable());
        assert!(segs[1].is_readable() && segs[1].is_writable() && !segs[1].is_executable());
    }

    #[test]
    fn read_overflow_at_u64_max_errors() {
        let (image, _) = build_elf(
            0x40_0000,
            &[SegSpec {
                vaddr: 0x40_0000,
                memsz: 0x1000,
                file_data: vec![0u8; 0x1000],
                perms: PF_R,
            }],
        );
        let loader = ElfLoader::from_bytes(image).unwrap();
        let err = loader
            .read_bytes(u64::MAX - 2, 16)
            .expect_err("should detect overflow");
        let msg = format!("{err:#}");
        assert!(msg.contains("overflow"), "got: {msg}");
    }
}
