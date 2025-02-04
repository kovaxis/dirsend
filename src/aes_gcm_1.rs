use crate::prelude::*;

use aes_gcm::{aead::AeadMutInPlace, Aes256Gcm, KeyInit};
use argon2::Argon2;

const AES_TAG_SIZE: usize = 16;
const AES_KEY_SIZE: usize = 32;
const U128_SIZE: usize = std::mem::size_of::<u128>();
const PLAINTEXT_CHUNK_SIZE: usize = 4 * 1024;
const SALT_SIZE: usize = 32;
pub const CIPHERTEXT_CHUNK_SIZE: usize = PLAINTEXT_CHUNK_SIZE + AES_TAG_SIZE;

fn init_aes_cipher(pass: &[u8], salt: [u8; 32]) -> Result<(Aes256Gcm, u128)> {
    let mut key = [0u8; AES_KEY_SIZE];
    Argon2::default()
        .hash_password_into(pass, &salt[..], &mut key)
        .map_err(|e| anyhow!("{}", e))
        .context("key derivation error")?;
    let cipher = Aes256Gcm::new(&key.into());
    let mut nonce = [0u8; U128_SIZE];
    nonce[..].copy_from_slice(&salt[..U128_SIZE]);
    Ok((cipher, u128::from_le_bytes(nonce)))
}

pub struct AesEncrypt<W: Write> {
    inner: W,
    cipher: Aes256Gcm,
    nonce: u128,
    buf: Vec<u8>,
}
impl<W: Write> AesEncrypt<W> {
    pub fn new(pass: &[u8], mut inner: W) -> Result<Self> {
        let salt = {
            let mut buf = [0u8; SALT_SIZE];
            getrandom::fill(&mut buf).map_err(|e| anyhow!("getrandom error: {}", e))?;
            buf
        };
        let (cipher, nonce) = init_aes_cipher(pass, salt)?;

        inner.write_all(&salt)?;
        let mut buf = Vec::with_capacity(CIPHERTEXT_CHUNK_SIZE);
        buf.extend(std::iter::repeat_n(0u8, AES_TAG_SIZE));
        Ok(Self {
            inner,
            cipher,
            nonce,
            buf,
        })
    }

    /// Assumes `self.buf` has length at least `AES_TAG_SIZE`.
    fn encrypt_buf(&mut self) -> io::Result<()> {
        // Get next nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.nonce.to_le_bytes()[..12]);
        self.nonce = self.nonce.saturating_add(1);
        // Encrypt buffer
        let tag: [u8; AES_TAG_SIZE] = self
            .cipher
            .encrypt_in_place_detached(&nonce.into(), &[], &mut self.buf[AES_TAG_SIZE..])
            .map_err(|_e| io::Error::new(io::ErrorKind::Other, "aes encryption error"))?
            .into();
        // Write tag into buffer
        self.buf[..AES_TAG_SIZE].copy_from_slice(&tag[..]);
        Ok(())
    }
}
impl<W> Write for AesEncrypt<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.buf.len() >= CIPHERTEXT_CHUNK_SIZE {
            self.flush()?;
        }
        let to_write = usize::min(buf.len(), CIPHERTEXT_CHUNK_SIZE - self.buf.len());
        self.buf.extend_from_slice(&buf[..to_write]);
        Ok(to_write)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.encrypt_buf()?;
        self.inner.write_all(&self.buf)?;
        self.buf.truncate(AES_TAG_SIZE);
        Ok(())
    }
}
impl<W> Drop for AesEncrypt<W>
where
    W: Write,
{
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

pub struct AesDecrypt<R> {
    inner: R,
    cipher: Aes256Gcm,
    nonce: u128,
    last_chunk: bool,
    buf: Box<[u8]>,
    buf_len: usize,
    buf_skip: usize,
}
impl<R: Read> AesDecrypt<R> {
    pub fn new(pass: &[u8], mut inner: R) -> Result<Self> {
        let mut salt = [0u8; 32];
        inner
            .read_exact(&mut salt)
            .context("extract aes-gcm-1 salt")?;
        let (cipher, nonce) = init_aes_cipher(pass, salt)?;

        let mut buf = vec![0u8; usize::max(SALT_SIZE, CIPHERTEXT_CHUNK_SIZE)].into_boxed_slice();
        buf[..SALT_SIZE].copy_from_slice(&salt[..]);
        Ok(Self {
            inner,
            cipher,
            nonce,
            buf,
            buf_len: 0,
            buf_skip: 0,
            last_chunk: false,
        })
    }

    /// Expects a buffer of size at least `CIPHERTEXT_CHUNK_SIZE`.
    fn fill_buf(&mut self) -> io::Result<usize> {
        // Read plaintext into buffer
        let mut filled = 0;
        while filled < CIPHERTEXT_CHUNK_SIZE {
            let n = self
                .inner
                .read(&mut self.buf[filled..CIPHERTEXT_CHUNK_SIZE])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled < CIPHERTEXT_CHUNK_SIZE {
            self.last_chunk = true;
        }
        if filled == 0 {
            return Ok(0);
        }
        // Extract tag from buffer
        if filled < AES_TAG_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected eof"));
        }
        let mut tag = [0u8; AES_TAG_SIZE];
        tag.copy_from_slice(&self.buf[..AES_TAG_SIZE]);
        // Get next nonce
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.nonce.to_le_bytes()[..12]);
        self.nonce = self.nonce.saturating_add(1);
        // Decrypt buffer
        self.cipher
            .decrypt_in_place_detached(
                &nonce.into(),
                &[],
                &mut self.buf[AES_TAG_SIZE..filled],
                &tag.into(),
            )
            .map_err(|_e| io::Error::new(io::ErrorKind::Other, "aes decryption error"))?;
        Ok(filled)
    }
}
impl<R> Read for AesDecrypt<R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Refill buffer if it is empty
        if self.buf_skip >= self.buf_len {
            // If we already reached the last chunk, short-circuit
            if self.last_chunk {
                return Ok(0);
            }
            // Fill the inner buffer
            let filled = self.fill_buf()?;
            if filled == 0 {
                return Ok(0);
            }
            self.buf_skip = AES_TAG_SIZE;
            self.buf_len = filled;
        }
        // Read from the buffer
        let to_read = usize::min(buf.len(), self.buf_len - self.buf_skip);
        buf[..to_read].copy_from_slice(&self.buf[self.buf_skip..self.buf_skip + to_read]);
        self.buf_skip += to_read;
        Ok(to_read)
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};

    use super::{AesDecrypt, AesEncrypt, CIPHERTEXT_CHUNK_SIZE, PLAINTEXT_CHUNK_SIZE};

    fn test_roundtrip(input: &[u8]) {
        let mut cipher = Vec::new();
        {
            let mut enc = AesEncrypt::new(b"my password", &mut cipher).unwrap();
            enc.write_all(input).unwrap();
        }
        let mut output = vec![];
        {
            let mut dec = AesDecrypt::new(b"my password", &cipher[..]).unwrap();
            dec.read_to_end(&mut output).unwrap();
        }
        assert_eq!(input, output);
    }

    #[test]
    fn roundtrip_0() {
        test_roundtrip(b"");
    }

    #[test]
    fn roundtrip_1() {
        test_roundtrip(b"x");
    }

    #[test]
    fn roundtrip_few() {
        test_roundtrip(b"hello world");
    }

    #[test]
    fn roundtrip_chunk() {
        let mut data = vec![0u8; CIPHERTEXT_CHUNK_SIZE];
        getrandom::fill(&mut data).unwrap();
        test_roundtrip(&data);
    }

    #[test]
    fn roundtrip_plain_chunk() {
        let mut data = vec![0u8; PLAINTEXT_CHUNK_SIZE];
        getrandom::fill(&mut data).unwrap();
        test_roundtrip(&data);
    }

    #[test]
    fn roundtrip_chunk_offbyone() {
        let mut data = vec![0u8; CIPHERTEXT_CHUNK_SIZE + 1];
        getrandom::fill(&mut data).unwrap();
        test_roundtrip(&data);
        let mut data = vec![0u8; CIPHERTEXT_CHUNK_SIZE - 1];
        getrandom::fill(&mut data).unwrap();
        test_roundtrip(&data);
    }

    #[test]
    fn roundtrip_plainchunk_offbyone() {
        let mut data = vec![0u8; PLAINTEXT_CHUNK_SIZE + 1];
        getrandom::fill(&mut data).unwrap();
        test_roundtrip(&data);
        let mut data = vec![0u8; PLAINTEXT_CHUNK_SIZE - 1];
        getrandom::fill(&mut data).unwrap();
        test_roundtrip(&data);
    }
}
