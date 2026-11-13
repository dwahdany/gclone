//! Streaming, ranged decryption of one file from its ticket (design §5, §7.2).
//!
//! The caller asks the store for the bytes `cipher_start()..cipher_end()` of the blob object
//! and pushes them here as they arrive, in pieces of any size; what comes back is plaintext
//! whose chunks have verified. All chunk arithmetic is here and is the main crate's
//! (`chunk_range`, `chunk_cipher_len`). Which chunk is the final one is decided from the
//! authenticated size in the ticket, never from the bytes — so a wrong byte, a chunk from
//! another place or another file, a missing chunk and a stream cut short all fail. A ranged
//! read starts at the first chunk it needs: the 60-byte stream header is never read.

use zeroize::Zeroizing;

use crate::crypto::{
    HEADER_LEN, Opener, chunk_cipher_len, chunk_count, chunk_range, ciphertext_len,
};
use crate::reader::{TICKET_VERSION, Ticket};
use crate::{Code, Error, Result, util};

pub struct FileReader {
    /// `None`: nothing to decrypt (an empty range, or a zero-length file).
    opener: Option<Opener>,
    size: u64,
    chunk_log2: u8,
    /// Blob offset of the file's stream (of its header).
    off: u64,
    /// Blob range to request.
    cipher: std::ops::Range<u64>,
    /// The chunk that is verified next.
    next: u64,
    /// Plaintext bytes of the first chunk that lie before the range.
    skip: usize,
    /// Plaintext bytes still owed.
    left: u64,
    /// The bytes of chunk `next` that have arrived so far.
    partial: Vec<u8>,
    /// Set by the first failure: nothing more comes out of this reader.
    failed: bool,
}

fn bad_input(what: impl Into<String>) -> Error {
    Error::new(Code::BadInput, what)
}

fn bad_ticket(what: &str) -> Error {
    bad_input(format!("ticket: {what}"))
}

impl FileReader {
    /// A reader for the plaintext bytes `start..end` of the ticket's file. `end` is clamped
    /// to the file's size; `start` beyond the size or beyond `end` is refused.
    pub fn from_json(ticket: &str, start: u64, end: u64) -> Result<FileReader> {
        let ticket: Ticket =
            serde_json::from_str(ticket).map_err(|_| bad_ticket("not a ticket of this viewer"))?;
        FileReader::new(&ticket, start, end)
    }

    pub fn new(ticket: &Ticket, start: u64, end: u64) -> Result<FileReader> {
        if ticket.v != TICKET_VERSION {
            return Err(bad_ticket("unknown version"));
        }
        let size = ticket.size;
        let end = end.min(size);
        if start > end {
            return Err(bad_input("the range starts after its end"));
        }
        let mut reader = FileReader {
            opener: None,
            size,
            chunk_log2: ticket.chunk_log2,
            off: ticket.off,
            cipher: 0..0,
            next: 0,
            skip: 0,
            left: end - start,
            partial: Vec::new(),
            failed: false,
        };
        let (key, header) = match (&ticket.key, &ticket.header) {
            (Some(key), Some(header)) => (key, header),
            // A zero-length file: no key, no location, nothing to fetch.
            (None, None) if size == 0 => return Ok(reader),
            _ => return Err(bad_ticket("key and header come together")),
        };
        let key: Zeroizing<Vec<u8>> =
            Zeroizing::new(util::unb64url(key).ok_or_else(|| bad_ticket("malformed key"))?);
        let key: Zeroizing<[u8; 32]> = Zeroizing::new(
            <[u8; 32]>::try_from(key.as_slice()).map_err(|_| bad_ticket("malformed key"))?,
        );
        let header = util::unb64url(header).ok_or_else(|| bad_ticket("malformed header"))?;
        let opener = Opener::from_ticket(key, &header)
            .map_err(|e| bad_ticket(&format!("unusable header ({e})")))?;
        // The ticket has to agree with itself, as the index entry it was made from did.
        let consistent = size > 0
            && opener.chunk_log2() == ticket.chunk_log2
            && ticket.clen == ciphertext_len(size, ticket.chunk_log2)
            && ticket.off.checked_add(ticket.clen).is_some();
        if !consistent {
            return Err(bad_ticket("size and location disagree"));
        }
        if let Some(span) = chunk_range(start..end, size, ticket.chunk_log2) {
            reader.cipher = ticket.off + span.cipher.start..ticket.off + span.cipher.end;
            (reader.next, reader.skip) = (span.first, span.skip);
            reader.opener = Some(opener);
        }
        Ok(reader)
    }

    /// The bytes of the blob object to request: `cipher_start()..cipher_end()` (the end is
    /// exclusive; `Range: bytes=<start>-<end - 1>`). Equal for an empty range: no request.
    pub fn cipher_start(&self) -> u64 {
        self.cipher.start
    }

    pub fn cipher_end(&self) -> u64 {
        self.cipher.end
    }

    /// Plaintext bytes still owed; `0` = the range is complete.
    pub fn remaining(&self) -> u64 {
        self.left
    }

    /// Where a request that broke off continues: the blob offset of the first chunk that has
    /// not verified. **Bytes of that chunk that arrived already are dropped** — the next bytes
    /// pushed must be the blob's bytes from this offset on.
    pub fn resume_at(&mut self) -> u64 {
        self.partial.clear();
        if self.left == 0 {
            return self.cipher.end;
        }
        let full = (1u64 << self.chunk_log2) + crate::crypto::TAG_LEN as u64;
        self.off + HEADER_LEN as u64 + self.next * full
    }

    /// Takes the next bytes of the requested blob range and returns the plaintext of the
    /// chunks they completed, cut to the range. Nothing of a chunk is returned before its tag
    /// verified. `corrupt`: a chunk did not verify, or bytes arrived after the range's end;
    /// after that the reader returns nothing more.
    pub fn push(&mut self, mut bytes: &[u8]) -> Result<Vec<u8>> {
        if self.failed {
            return Err(Error::new(
                Code::Corrupt,
                "the file could not be read: an earlier part of it did not verify",
            ));
        }
        let mut out = Vec::new();
        if self.left > 0 {
            // At most what this push can complete: the bytes in hand, less one tag per chunk.
            let owed = usize::try_from(self.left).unwrap_or(usize::MAX);
            out.reserve((self.partial.len() + bytes.len()).min(owed.saturating_add(self.skip)));
        }
        while !bytes.is_empty() {
            let Some(opener) = self.opener.as_ref().filter(|_| self.left > 0) else {
                return self.fail("data after the end of the requested range");
            };
            let need = chunk_cipher_len(self.next, self.size, self.chunk_log2);
            let last = self.next + 1 == chunk_count(self.size, self.chunk_log2);
            let before = out.len();
            let opened = if self.partial.is_empty() && bytes.len() >= need {
                // A whole chunk in the input: opened from where it is.
                let (chunk, rest) = bytes.split_at(need);
                bytes = rest;
                opener.open_chunk(self.next, last, chunk, &mut out)
            } else {
                let take = (need - self.partial.len()).min(bytes.len());
                let (head, rest) = bytes.split_at(take);
                self.partial.extend_from_slice(head);
                bytes = rest;
                if self.partial.len() < need {
                    break;
                }
                let opened = opener.open_chunk(self.next, last, &self.partial, &mut out);
                self.partial.clear();
                opened
            };
            if opened.is_err() {
                out.truncate(before);
                return self.fail("a part of it is damaged (authentication failed)");
            }
            // Cut to the range: the first chunk's lead, the last chunk's tail.
            if self.skip > 0 {
                out.drain(before..before + self.skip);
                self.skip = 0;
            }
            let fresh = (out.len() - before) as u64;
            if fresh > self.left {
                out.truncate(before + self.left as usize);
            }
            self.left -= fresh.min(self.left);
            self.next += 1;
        }
        Ok(out)
    }

    fn fail<T>(&mut self, what: &str) -> Result<T> {
        self.failed = true;
        self.partial = Vec::new();
        Err(Error::new(
            Code::Corrupt,
            format!("the file could not be read: {what}"),
        ))
    }
}
