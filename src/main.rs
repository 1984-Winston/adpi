use std::{
    mem::{size_of, MaybeUninit},
    net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream},
    os::fd::AsRawFd,
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use linux_raw_sys::net::tcp_info;
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
    time,
};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Number of worker threads
    #[arg(short = 't', long, default_value_t = 4)]
    threads: usize,

    /// Socket addresses to bind listeners
    #[arg(short = 'l', long, default_values = ["127.0.0.1:1280", "[::1]:1280"])]
    listen_address: Vec<SocketAddr>,

    /// Split positions in TLS ClientHello message
    #[arg(short = 'c', long)]
    split_positions: Vec<usize>,

    /// Split TLS ClientHello at host
    #[arg(short = 's', long, default_value_t = false)]
    split_host: bool,

    /// Set fwmark for outgoing sockets. Disabled if 0.
    #[arg(short = 'm', long, default_value_t = 1280)]
    fwmark: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.threads > 1 {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(_main(args))
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(args.threads)
            .enable_all()
            .build()?
            .block_on(_main(args))
    }
}

async fn _main(args: Args) -> Result<()> {
    let args = Arc::new(args);

    for addr in &args.listen_address {
        let listener = make_listener(*addr)?;
        println!("listening on {addr}");

        let args = Arc::clone(&args);
        tokio::spawn(async move {
            loop {
                if let Ok((client_stream, client_addr)) = listener.accept().await {
                    tokio::spawn(handle_client(client_stream, client_addr, Arc::clone(&args)));
                }
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn make_listener(addr: SocketAddr) -> Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let listen_socket = Socket::new(domain, Type::STREAM, None)?;
    listen_socket.set_nonblocking(true)?;
    listen_socket.set_cloexec(true)?;
    listen_socket.set_reuse_address(true)?;
    listen_socket.set_nodelay(true)?;
    listen_socket.set_ip_transparent(true)?;
    listen_socket.bind(&addr.into())?;
    listen_socket.listen(1024)?;

    let std_listener: StdTcpListener = listen_socket.into();
    let listener = TcpListener::from_std(std_listener)?;
    Ok(listener)
}

fn get_tcp_info(fd: i32) -> Result<tcp_info> {
    unsafe {
        let mut payload: MaybeUninit<tcp_info> = MaybeUninit::uninit();
        let mut len = size_of::<tcp_info>() as libc::socklen_t;

        if libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            payload.as_mut_ptr().cast(),
            &mut len,
        ) == 0
        {
            let payload = payload.assume_init();
            Ok(payload)
        } else {
            Err(anyhow!("getsockopt failed"))
        }
    }
}

async fn really_flush(writer: &mut OwnedWriteHalf, fd: i32) -> Result<()> {
    writer.flush().await?;

    let mut timeout = 1;
    while get_tcp_info(fd)?.tcpi_notsent_bytes > 0 {
        time::sleep(time::Duration::from_millis(timeout)).await;
        if timeout < 8 {
            timeout *= 2;
        }
    }

    Ok(())
}

async fn client_to_server(
    mut reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    fd: i32,
    args: Arc<Args>,
) -> Result<()> {
    let mut buf = vec![0u8; 8192];
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
                really_flush(&mut writer, fd).await?;
            }
            start_byte = *split_at;
        }
    }

    writer.shutdown().await?;
    Ok(())
}

async fn server_to_client(mut reader: OwnedReadHalf, mut writer: OwnedWriteHalf) -> Result<()> {
    tokio::io::copy(&mut reader, &mut writer).await?;
    Ok(())
}

async fn handle_client(
    client_stream: TcpStream,
    client_addr: SocketAddr,
    args: Arc<Args>,
) -> Result<()> {
    client_stream.set_nodelay(true)?;
    let (client_stream, original_dst) = get_original_dst(client_stream)?;
    eprintln!("{client_addr} -> {original_dst}");

    let dst_domain = if original_dst.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let dst_socket = Socket::new(dst_domain, Type::STREAM, None)?;
    dst_socket.set_nonblocking(true)?;
    dst_socket.set_cloexec(true)?;
    dst_socket.set_reuse_address(true)?;
    dst_socket.set_nodelay(true)?;
    if args.fwmark != 0 {
        dst_socket.set_mark(args.fwmark)?;
    }
    dst_socket.connect(&original_dst.into()).ok();
    let std_stream: StdTcpStream = dst_socket.into();
    let server_stream = TcpStream::from_std(std_stream)?;

    let server_fd = server_stream.as_raw_fd();

    let (client_reader, client_writer) = client_stream.into_split();
    let (server_reader, server_writer) = server_stream.into_split();

    tokio::spawn(client_to_server(
        client_reader,
        server_writer,
        server_fd,
        Arc::clone(&args),
    ));
    tokio::spawn(server_to_client(server_reader, client_writer));

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
