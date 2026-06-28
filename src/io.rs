//! Random-access byte source/sink abstraction for the data plane.
//!
//! girth's NACK retransmit re-sends arbitrary earlier blocks and the receiver
//! writes blocks out of order, so the data plane needs **positional** (not
//! streaming) access. The sender reads blocks at arbitrary offsets; the receiver
//! writes them at arbitrary offsets and flushes at the end. These two traits
//! capture exactly that, so an embedder can move bytes straight from / into RAM
//! (`MemSource` / `MemSink`) instead of staging through a temp file.
//!
//! The file-backed impls (`FileSource` / `FileSink`) wrap the same positional
//! `sys::` calls the CLI has always used, so the on-disk behaviour is unchanged.
//!
//! Wire impact: none — this is purely an internal I/O-source refactor. The
//! whole-content CRC32C is computed over the source bytes regardless of backing.

use crate::protocol::crc32c_append;
use std::fs::File;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Source of bytes for the sender. Must support concurrent positional reads:
/// the prefetch thread reads ahead while retransmits re-read arbitrary blocks.
pub trait BlockSource: Send + Sync {
    /// Total length in bytes.
    fn len(&self) -> u64;

    /// Reads exactly `buf.len()` bytes starting at byte `off`, independent of
    /// any cursor (safe for concurrent positional reads from many threads).
    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Sink for the receiver: positional, out-of-order writes; `finalize` flushes.
pub trait BlockSink: Send + Sync {
    /// Sizes the destination to `len` up front so scattered writes are plain
    /// overwrites rather than appends.
    fn allocate(&self, len: u64) -> io::Result<()>;

    /// Writes all of `buf` starting at byte `off`, independent of any cursor.
    fn write_all_at(&self, off: u64, buf: &[u8]) -> io::Result<()>;

    /// Optional asynchronous-writeback hint over `[off, off+len)` (the
    /// file-backed sink maps this to `sync_file_range` on Linux). Default no-op.
    fn sync_range(&self, _off: i64, _len: i64) {}

    /// Flushes any buffered state. Called once after all writes succeed.
    fn finalize(&self) -> io::Result<()> {
        Ok(())
    }

    /// Returns the CRC32C of everything written so far for the end-to-end
    /// integrity check, or `None` if read-back is unsupported. Both built-in
    /// sinks support it.
    fn read_crc32c(&self) -> io::Result<Option<u32>> {
        Ok(None)
    }
}

/// Computes the whole-source CRC32C by streaming positional reads — the value
/// the sender puts in the handshake for the receiver to verify.
pub fn source_crc32c(src: &dyn BlockSource) -> io::Result<u32> {
    let total = src.len();
    let mut crc = 0u32;
    let mut off = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    while off < total {
        let n = ((total - off) as usize).min(buf.len());
        src.read_exact_at(off, &mut buf[..n])?;
        crc = crc32c_append(crc, &buf[..n]);
        off += n as u64;
    }
    Ok(crc)
}

// --- file-backed impls (CLI / on-disk; behaviour unchanged) -----------------

/// A `BlockSource` over a real seekable file.
pub struct FileSource {
    file: Arc<File>,
    len: u64,
}

impl FileSource {
    pub fn open(path: &str) -> io::Result<FileSource> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(FileSource {
            file: Arc::new(file),
            len,
        })
    }

    pub fn from_file(file: File) -> io::Result<FileSource> {
        let len = file.metadata()?.len();
        Ok(FileSource {
            file: Arc::new(file),
            len,
        })
    }
}

impl BlockSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        crate::sys::read_exact_at(&self.file, buf, off)
    }
}

/// A `BlockSink` over a real seekable file, preferring `fallocate` so scattered
/// retransmit writes land as plain overwrites.
pub struct FileSink {
    file: Arc<File>,
    len: AtomicU64,
}

impl FileSink {
    pub fn create(path: &str) -> io::Result<FileSink> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        Ok(FileSink {
            file: Arc::new(file),
            len: AtomicU64::new(0),
        })
    }

    pub fn from_file(file: File) -> FileSink {
        FileSink {
            file: Arc::new(file),
            len: AtomicU64::new(0),
        }
    }
}

impl BlockSink for FileSink {
    fn allocate(&self, len: u64) -> io::Result<()> {
        self.len.store(len, Ordering::Relaxed);
        let size = len as i64;
        if size > 0 && crate::sys::fallocate(&self.file, size).is_ok() {
            return Ok(());
        }
        self.file.set_len(len)
    }
    fn write_all_at(&self, off: u64, buf: &[u8]) -> io::Result<()> {
        crate::sys::write_all_at(&self.file, buf, off)
    }
    fn sync_range(&self, off: i64, len: i64) {
        crate::sys::sync_file_range_write(&self.file, off, len);
    }
    fn finalize(&self) -> io::Result<()> {
        self.file.sync_all()
    }
    fn read_crc32c(&self) -> io::Result<Option<u32>> {
        let len = self.len.load(Ordering::Relaxed);
        let mut crc = 0u32;
        let mut off = 0u64;
        let mut buf = vec![0u8; 1 << 20];
        while off < len {
            let n = ((len - off) as usize).min(buf.len());
            crate::sys::read_exact_at(&self.file, &mut buf[..n], off)?;
            crc = crc32c_append(crc, &buf[..n]);
            off += n as u64;
        }
        Ok(Some(crc))
    }
}

// --- in-memory impls (embedders move bytes straight from / into RAM) --------

/// A `BlockSource` over any in-memory byte buffer (`Vec<u8>`, `Arc<[u8]>`,
/// `bytes::Bytes`, …) — anything that is `AsRef<[u8]>`. Zero-copy: the bytes are
/// read in place.
pub struct MemSource<T>(T);

impl<T: AsRef<[u8]> + Send + Sync> MemSource<T> {
    pub fn new(data: T) -> MemSource<T> {
        MemSource(data)
    }
}

impl<T: AsRef<[u8]> + Send + Sync> BlockSource for MemSource<T> {
    fn len(&self) -> u64 {
        self.0.as_ref().len() as u64
    }
    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let data = self.0.as_ref();
        let start = off as usize;
        let end = start.checked_add(buf.len()).ok_or_else(bad_range)?;
        if end > data.len() {
            return Err(bad_range());
        }
        buf.copy_from_slice(&data[start..end]);
        Ok(())
    }
}

/// A `BlockSink` collecting the transfer into a single in-memory buffer. After a
/// successful transfer the embedder reads the bytes out with [`MemSink::to_vec`]
/// or [`MemSink::with_bytes`], or unwraps a uniquely-held `Arc` via
/// [`MemSink::into_vec`].
pub struct MemSink {
    buf: Mutex<Vec<u8>>,
}

impl Default for MemSink {
    fn default() -> Self {
        MemSink::new()
    }
}

impl MemSink {
    pub fn new() -> MemSink {
        MemSink {
            buf: Mutex::new(Vec::new()),
        }
    }

    /// Runs `f` over the collected bytes without copying them out.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.buf.lock().unwrap())
    }

    /// Copies the collected bytes out.
    pub fn to_vec(&self) -> Vec<u8> {
        self.buf.lock().unwrap().clone()
    }

    /// Consumes a uniquely-held sink and returns the buffer without copying.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf.into_inner().unwrap()
    }
}

impl BlockSink for MemSink {
    fn allocate(&self, len: u64) -> io::Result<()> {
        let mut b = self.buf.lock().unwrap();
        b.clear();
        b.resize(len as usize, 0);
        Ok(())
    }
    fn write_all_at(&self, off: u64, src: &[u8]) -> io::Result<()> {
        let mut b = self.buf.lock().unwrap();
        let start = off as usize;
        let end = start.checked_add(src.len()).ok_or_else(bad_range)?;
        if end > b.len() {
            // allocate() normally sizes us up front; grow defensively otherwise.
            b.resize(end, 0);
        }
        b[start..end].copy_from_slice(src);
        Ok(())
    }
    fn read_crc32c(&self) -> io::Result<Option<u32>> {
        let b = self.buf.lock().unwrap();
        Ok(Some(crc32c_append(0, &b)))
    }
}

fn bad_range() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "positional access out of range",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_source_positional_reads() {
        let src = MemSource::new(vec![0u8, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(src.len(), 8);
        let mut b = [0u8; 3];
        src.read_exact_at(2, &mut b).unwrap();
        assert_eq!(b, [2, 3, 4]);
        // Out-of-range reads error rather than panic.
        assert!(src.read_exact_at(6, &mut [0u8; 4]).is_err());
        assert!(src.read_exact_at(u64::MAX, &mut [0u8; 1]).is_err());
    }

    #[test]
    fn mem_sink_out_of_order_writes_and_crc() {
        let sink = MemSink::new();
        sink.allocate(6).unwrap();
        // Write out of order, as the receiver does.
        sink.write_all_at(3, &[3, 4, 5]).unwrap();
        sink.write_all_at(0, &[0, 1, 2]).unwrap();
        assert_eq!(sink.to_vec(), vec![0, 1, 2, 3, 4, 5]);
        let want = crc32c_append(0, &[0, 1, 2, 3, 4, 5]);
        assert_eq!(sink.read_crc32c().unwrap(), Some(want));
    }

    #[test]
    fn source_crc_matches_direct() {
        let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let direct = crc32c_append(0, &data);
        let src = MemSource::new(data);
        assert_eq!(source_crc32c(&src).unwrap(), direct);
    }
}
