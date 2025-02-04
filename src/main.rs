mod prelude {
    pub use anyhow::{anyhow, bail, ensure, Context, Result};
    pub use serde::{Deserialize, Serialize};
    pub use std::{
        fmt,
        io::{self, BufReader, Read, Write},
        path::PathBuf,
        time::Duration,
    };
}

use crate::prelude::*;
use std::{
    fs::File,
    net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs},
};

use aes_gcm_1::{AesDecrypt, AesEncrypt, CIPHERTEXT_CHUNK_SIZE};
use console::{style, Term};
use flate2::{bufread::GzEncoder, read::GzDecoder};

const PROTOCOL_VERSION: (u32, u32) = (1, 0);
const DEFAULT_PORT: u16 = 56273;

mod aes_gcm_1;

enum Action {
    Send,
    Recv,
}

fn ask_char<T>(
    mut term: &Term,
    s: impl fmt::Display,
    mut acc: impl FnMut(char) -> Option<T>,
) -> Result<T> {
    write!(term, "{} ", style(s).cyan().bold())?;
    loop {
        let c = term.read_char()?;
        match acc(c) {
            Some(t) => {
                writeln!(term, "{}", c)?;
                break Ok(t);
            }
            None => {}
        }
    }
}

fn ask_line(
    mut term: &Term,
    s: impl fmt::Display,
    mut acc: impl FnMut(&str) -> bool,
) -> Result<String> {
    write!(term, "{}: ", style(s).cyan().bold())?;
    loop {
        let r = term.read_line()?;
        if acc(&r) {
            break Ok(r);
        }
    }
}
fn ask_secure_line(
    mut term: &Term,
    s: impl fmt::Display,
    mut acc: impl FnMut(&str) -> bool,
) -> Result<String> {
    write!(term, "{}: ", style(s).cyan().bold())?;
    loop {
        let s = term.read_secure_line()?;
        if acc(&s) {
            break Ok(s);
        }
    }
}

pub fn main() -> Result<()> {
    let term = Term::stdout();
    let action = ask_char(
        &term,
        style("Do you want to send or receive? (S/R)").cyan(),
        |c| match c {
            's' | 'S' => Some(Action::Send),
            'r' | 'R' => Some(Action::Recv),
            _ => None,
        },
    )?;
    match action {
        Action::Send => {
            send(term)?;
        }
        Action::Recv => {
            recv(term)?;
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Header {
    protocol: String,
    version: (u32, u32),
    filename: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    encryption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    compression: Option<String>,
}

fn send_value<T: Serialize>(stream: &mut TcpStream, value: T) -> Result<()> {
    let buf = serde_json::to_vec(&value)?;
    let len = u16::try_from(buf.len()).context("json is too long")?;
    let len_buf = len.to_le_bytes();
    stream.write_all(&len_buf).context("network upload error")?;
    stream.write_all(&buf).context("network upload error")?;
    Ok(())
}

fn recv_value<T>(stream: &mut TcpStream) -> Result<T>
where
    T: for<'a> Deserialize<'a>,
{
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .context("network download error")?;
    let len = u16::from_le_bytes(len_buf);
    let mut raw = vec![0u8; len as usize];
    stream
        .read_exact(&mut raw)
        .context("network download error")?;
    let val: T = serde_json::from_slice(&raw[..]).context("received malformed data")?;
    Ok(val)
}

fn send(term: Term) -> Result<()> {
    let path = PathBuf::from(ask_line(
        &term,
        "Enter the path of the file/directory to send",
        |_| true,
    )?);
    let filename = path.file_name().ok_or_else(|| anyhow!("invalid path"))?;
    let filename = filename
        .to_str()
        .ok_or_else(|| anyhow!("invalid utf-8 path"))?
        .to_string();
    let file = File::open(&path).context("open file")?;
    let file = BufReader::new(file);

    let pass = ask_secure_line(&term, "Enter password", |_| true)?;

    let file = GzEncoder::new(file, flate2::Compression::fast());
    let mut file = AesEncrypt::new(pass.as_bytes(), file)?;
    let listener = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, DEFAULT_PORT))?;
    println!("Listening on port {DEFAULT_PORT}...");
    let (mut stream, addr) = listener.accept()?;
    println!("Connection from {}, beaming over...", addr);
    send_value(
        &mut stream,
        Header {
            protocol: "dirsend".into(),
            version: PROTOCOL_VERSION,
            filename,
            encryption: Some("aes-gcm-1".into()),
            compression: Some("gzip".into()),
        },
    )?;
    let mut buf = vec![0u8; CIPHERTEXT_CHUNK_SIZE];
    loop {
        let read_bytes = file.read(&mut buf[..]).context("file read error")?;
        if read_bytes == 0 {
            break;
        }
        stream
            .write_all(&buf[..read_bytes])
            .context("network upload error")?;
    }
    println!(
        "{} Uploaded file at {}",
        style("Success!").green().bold(),
        path.display(),
    );
    Ok(())
}

fn parse_host(host: &str) -> Result<Vec<SocketAddr>> {
    if let Ok(addrs) = host.to_socket_addrs() {
        return Ok(addrs.collect());
    }
    (host, DEFAULT_PORT)
        .to_socket_addrs()
        .map(|addrs| addrs.collect())
        .context("could not resolve hostname")
}

fn connect_to_host(host: &str) -> Result<TcpStream> {
    let addrs = parse_host(&host)?;
    if addrs.is_empty() {
        bail!("host does not resolve to any ips")
    }
    let mut errs = vec![];
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(6)) {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                errs.push(err);
            }
        }
    }
    let mut msg = "failed to resolve host:".to_string();
    for err in errs {
        use std::fmt::Write;
        write!(msg, "\n  {}", err)?;
    }
    bail!("{msg}");
}

fn recv(term: Term) -> Result<()> {
    let host = ask_line(&term, "Enter the address of the remote server", |_| true)?;
    let mut stream = connect_to_host(&host)?;
    let header: Header = recv_value(&mut stream)?;
    ensure!(header.protocol == "dirsend", "invalid protocol");
    ensure!(header.version.0 == 1, "incompatible protocol version");

    let filename = header.filename.trim_ascii();
    let banned = b"\0/\\";
    ensure!(
        !banned.iter().any(|ban| filename.as_bytes().contains(ban)),
        "invalid filename"
    );
    ensure!(filename != "..", "invalid filename");
    let mut path = PathBuf::from(filename);
    ensure!(path.iter().count() == 1, "invalid filename");
    ensure!(path.is_relative(), "invalid filename");
    let mut counter = 1;
    while path.exists() {
        counter += 1;
        let (stem, ext) = match filename.find('.') {
            None | Some(0) => (filename, ""),
            Some(pos) => filename.split_at(pos),
        };
        path = PathBuf::from(format!("{stem} ({counter}){ext}"));
    }
    if counter > 1 {
        println!(
            "{}",
            style(format!(
                "File {} already exists, downloading to {}",
                filename,
                path.display(),
            ))
            .yellow()
        );
    }

    let mut stream: &mut dyn Read = &mut stream;
    let mut decrypter;
    match header.encryption.as_deref() {
        None => {}
        Some("aes-gcm-1") => {
            println!("Contents encrypted with aes-gcm-1");
            let pass = ask_secure_line(&term, "Enter password", |_| true)?;
            decrypter = AesDecrypt::new(pass.as_bytes(), stream)?;
            stream = &mut decrypter;
        }
        Some(unk) => {
            bail!("unknown encryption mode '{unk}'")
        }
    }
    let mut deflater;
    match header.compression.as_deref() {
        None => {}
        Some("gzip") => {
            println!("Using gzip compression");
            deflater = GzDecoder::new(stream);
            stream = &mut deflater;
        }
        Some(unk) => {
            bail!("unknown compression mode '{unk}'")
        }
    }

    let mut file = File::create_new(&path)?;
    let mut buf = vec![0u8; CIPHERTEXT_CHUNK_SIZE];
    loop {
        let read_bytes = stream
            .read(&mut buf[..])
            .context("network download error")?;
        if read_bytes == 0 {
            break;
        }
        file.write_all(&buf[..read_bytes])
            .context("file write error")?;
    }

    println!(
        "{} Downloaded to {}",
        style("Success!").green().bold(),
        path.display(),
    );

    Ok(())
}
