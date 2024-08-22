use std::{
    net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream},
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result};
use clap::Parser;
use socket2::{Domain, Socket, Type};
use tls_parser::{
    parse_tls_client_hello_extensions, parse_tls_plaintext, SNIType, TlsExtension, TlsMessage,
    TlsMessageHandshake,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Number of worker threads
    #[arg(short = 't', long, default_value_t = 4)]
    threads: usize,

    /// Socket address to bind listener
    #[arg(short = 'l', long, default_value = "127.0.0.1:1280")]
    listen_address: String,

    /// Rx buffer size
    #[arg(short = 'r', long, default_value_t = 32 * 1024)]
    rx_buffer_size: usize,

    /// Socket listen backlog
    #[arg(short = 'b', long, default_value_t = 1024)]
    listen_backlog: i32,

    /// Split positions in TLS ClientHello message
    #[arg(short = 'c', long)]
    split_positions: Vec<usize>,

    /// Split TLS ClientHello at host
    #[arg(short = 's', long, default_value_t = false)]
    split_host: bool,

    /// Set fwmark
    #[arg(short = 'f', long)]
    fwmark: Option<u32>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.threads)
        .enable_io()
        .build()?
        .block_on(_main(args))
}

async fn _main(args: Args) -> Result<()> {
    let listen_addr = SocketAddr::from_str(&args.listen_address)?;

    let domain = if listen_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let listen_socket = Socket::new(domain, Type::STREAM, None)?;
    listen_socket.set_reuse_address(true)?;
    listen_socket.set_nonblocking(true)?;
    listen_socket.set_ip_transparent(true)?;
    listen_socket.set_recv_buffer_size(args.rx_buffer_size)?;
    listen_socket.bind(&listen_addr.into())?;
    listen_socket.listen(args.listen_backlog)?;

    let std_listener: StdTcpListener = listen_socket.into();
    let listener = TcpListener::from_std(std_listener)?;

    let args = Arc::new(args);
    loop {
        if let Ok((client_stream, client_addr)) = listener.accept().await {
            tokio::spawn(handle_client(client_stream, client_addr, Arc::clone(&args)));
        }
    }
}

async fn copy_stream(
    mut reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    args: Arc<Args>,
) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    let mut split_positions = Vec::with_capacity(8);

    loop {
        split_positions.clear();

        let Ok(read_bytes) = reader.read(&mut buf).await else {
            break;
        };
        if read_bytes == 0 {
            break;
        }

        if let Ok((_, record)) = parse_tls_plaintext(&buf) {
            for msg in record.msg {
                if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
                    if let Some(exts) = ch.ext {
                        if let Ok((_, exts)) = parse_tls_client_hello_extensions(exts) {
                            for ext in exts {
                                if let TlsExtension::SNI(snis) = ext {
                                    for (sni_type, sni_data) in snis {
                                        if sni_type == SNIType::HostName {
                                            for pos in &args.split_positions {
                                                if *pos < read_bytes {
                                                    split_positions.push(*pos);
                                                }
                                            }

                                            if args.split_host {
                                                let start_of_hostname = sni_data.as_ptr() as usize
                                                    - buf.as_ptr() as usize;
                                                if sni_data.len() >= 2 {
                                                    split_positions.push(start_of_hostname + 1);
                                                } else {
                                                    split_positions.push(start_of_hostname);
                                                };
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        split_positions.push(read_bytes);
        split_positions.sort_unstable();
        split_positions.dedup();

        let mut start_byte = 0usize;
        for split_at in &split_positions {
            writer.write_all(&buf[start_byte..*split_at]).await?;
            if split_positions.len() > 1 && *split_at != read_bytes {
                writer.flush().await?;
            }
            start_byte = *split_at;
        }
    }

    writer.shutdown().await?;
    Ok(())
}

async fn handle_client(
    client_stream: TcpStream,
    client_addr: SocketAddr,
    args: Arc<Args>,
) -> Result<()> {
    let (client_stream, original_dst) = get_original_dst(client_stream)?;
    eprintln!("{client_addr} -> {original_dst}");

    let dst_domain = if original_dst.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let dst_socket = Socket::new(dst_domain, Type::STREAM, None)?;
    dst_socket.set_reuse_address(true)?;
    dst_socket.set_nonblocking(true)?;
    if let Some(fwmark) = args.fwmark {
        dst_socket.set_mark(fwmark)?;
    }
    dst_socket.connect(&original_dst.into()).ok();
    let std_stream: StdTcpStream = dst_socket.into();
    let server_stream = TcpStream::from_std(std_stream)?;

    let (client_reader, client_writer) = client_stream.into_split();
    let (server_reader, server_writer) = server_stream.into_split();

    tokio::spawn(copy_stream(client_reader, server_writer, Arc::clone(&args)));
    tokio::spawn(copy_stream(server_reader, client_writer, args));

    Ok(())
}

fn get_original_dst(stream: TcpStream) -> Result<(TcpStream, SocketAddr)> {
    let std_stream = stream.into_std()?;
    let socket2_socket = Socket::from(std_stream);
    let original_dst = socket2_socket
        .original_dst()?
        .as_socket()
        .context("socket is not inet")?;
    let std_stream: StdTcpStream = socket2_socket.into();
    let stream = TcpStream::from_std(std_stream)?;
    Ok((stream, original_dst))
}
