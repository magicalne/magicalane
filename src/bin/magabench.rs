//! magabench - transport benchmark tool for magicalane.
//!
//! Two modes:
//!   magabench echo --listen 0.0.0.0:9807
//!       Framed TCP server used as the benchmark origin (runs in its own
//!       container on the test network).
//!   magabench run --socks 127.0.0.1:1080 --target bench:9807
//!       Drives the full client stack (socks5 -> transport -> server ->
//!       echo) and reports latency / throughput / concurrency metrics.
//!
//! Frame format (both directions):
//!   [u32 BE len][payload]      len >= 1, payload[0] = command byte
//! Commands:
//!   0x01 PING  [junk]          -> echoed verbatim (RTT measurement)
//!   0x02 BENCH [u32 BE total]  -> server streams `total` payload bytes
//!                                 back in DATA frames (download)
//!   0x03 DATA  [junk]          (server -> client only)
//!   0x04 SINK  [u32 BE total][junk...] -> client streams `total` junk
//!                                 bytes in the same frame; server ACKs
//!   0x05 ACK   [u32 BE got]    (server -> client, end of SINK)

use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};

use rand::Rng;
use structopt::StructOpt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Barrier,
};

const CHUNK: usize = 64 * 1024;

#[derive(StructOpt)]
#[structopt(name = "magabench", about = "magicalane transport benchmark")]
enum Cmd {
    /// Benchmark origin: framed echo/bench server.
    Echo {
        #[structopt(long, default_value = "0.0.0.0:9807")]
        listen: String,
    },
    /// Drive the benchmark through the socks5 client.
    Run {
        #[structopt(long, default_value = "127.0.0.1:1080")]
        socks: String,
        /// SOCKS5 CONNECT target (domain:port, resolved remotely).
        #[structopt(long, default_value = "bench:9807")]
        target: String,
        /// Print machine-readable key=value lines instead of a report.
        #[structopt(long)]
        pairs: bool,
        #[structopt(long, default_value = "50")]
        pings: usize,
        #[structopt(long, default_value = "20")]
        connects: usize,
        #[structopt(long, default_value = "16")]
        conc_conns: usize,
        #[structopt(long, default_value = "20")]
        conc_pings: usize,
        /// Download bytes (64 MiB).
        #[structopt(long, default_value = "67108864")]
        dl_bytes: usize,
        /// Upload bytes (32 MiB).
        #[structopt(long, default_value = "33554432")]
        ul_bytes: usize,
        /// Parallel download connections for the aggregate metric.
        #[structopt(long, default_value = "4")]
        dl_par: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cmd = Cmd::from_args();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        match cmd {
            Cmd::Echo { listen } => echo_server(&listen).await,
            Cmd::Run {
                socks,
                target,
                pairs,
                pings,
                connects,
                conc_conns,
                conc_pings,
                dl_bytes,
                ul_bytes,
                dl_par,
            } => run_bench(&socks, &target, pairs, pings, connects, conc_conns, conc_pings, dl_bytes, ul_bytes, dl_par).await,
        }
    })
}

// ---------------------------------------------------------------- echo server

async fn echo_server(listen: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    eprintln!("magabench echo listening on {}", listener.local_addr()?);
    loop {
        let (stream, _) = listener.accept().await?;
        let stream = stream;
        stream.set_nodelay(true).ok();
        tokio::spawn(async move {
            if let Err(err) = handle_echo(stream).await {
                eprintln!("echo conn error: {err}");
            }
        });
    }
}

async fn handle_echo(mut stream: TcpStream) -> io::Result<()> {
    loop {
        let payload = read_frame(&mut stream).await?;
        let cmd = payload[0];
        match cmd {
            0x01 => write_frame(&mut stream, &payload).await?,
            0x02 => {
                let total = be32(&payload[1..5]) as usize;
                let junk = vec![0x41u8; CHUNK];
                let mut sent = 0;
                while sent < total {
                    let data = (CHUNK - 1).min(total - sent);
                    let plen = data + 1; // cmd byte + data bytes
                    stream.write_all(&(plen as u32).to_be_bytes()).await?;
                    stream.write_all(&[0x03u8]).await?;
                    stream.write_all(&junk[..data]).await?;
                    sent += data;
                }
                stream.flush().await?;
            }
            0x04 => {
                // payload = [0x04][u32 total][junk...] - consume junk, ACK.
                let total = be32(&payload[1..5]) as usize;
                let _ = total; // payload already read into memory by read_frame
                let ack = {
                    let mut f = vec![0x05u8];
                    f.extend_from_slice(&(total as u32).to_be_bytes());
                    f
                };
                write_frame(&mut stream, &ack).await?;
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------- frames

async fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    let len = be32(&hdr) as usize;
    if len == 0 || len > (64 << 20) + 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad frame len"));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    stream.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

// ---------------------------------------------------------------- bench client

async fn socks_connect(socks: &str, target: &str) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect(socks).await?;
    s.set_nodelay(true).ok();
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await?;
    if b != [0x05, 0x00] {
        return Err(io::Error::other("socks5 hello refused"));
    }
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad port"))?),
        None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "target must be host:port")),
    };
    if host.is_empty() || host.len() > 255 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad host"));
    }
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    if hdr[1] != 0 {
        return Err(io::Error::other(format!("socks5 connect failed: {}", hdr[1])));
    }
    let skip = match hdr[3] {
        0x01 => 4 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        0x04 => 16 + 2,
        other => return Err(io::Error::other(format!("bad atyp {other}"))),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await?;
    Ok(s)
}

async fn ping_rtt(stream: &mut TcpStream, size: usize, scratch: &mut Vec<u8>) -> io::Result<Duration> {
    scratch.resize(size, 0);
    rand::thread_rng().fill(scratch.as_mut_slice());
    scratch[0] = 0x01;
    let start = Instant::now();
    write_frame(stream, scratch).await?;
    let echoed = read_frame(stream).await?;
    let dt = start.elapsed();
    if echoed.len() != size {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "echo size mismatch"));
    }
    Ok(dt)
}

#[allow(clippy::too_many_arguments)]
async fn run_bench(
    socks: &str,
    target: &str,
    pairs: bool,
    pings: usize,
    connects: usize,
    conc_conns: usize,
    conc_pings: usize,
    dl_bytes: usize,
    ul_bytes: usize,
    dl_par: usize,
) -> anyhow::Result<()> {
    let mut metrics: Vec<(String, f64)> = Vec::new();
    let mut put = |k: &str, v: f64| metrics.push((k.to_string(), v));

    // -- warmup + one shared connection for latency/throughput
    let mut s = socks_connect(socks, target).await?;

    // 1) connect time (fresh proxied connection, incl. any session setup)
    let mut times = Vec::new();
    for _ in 0..connects {
        let t = Instant::now();
        let c = socks_connect(socks, target).await?;
        let dt = t.elapsed();
        drop(c);
        times.push(dt.as_secs_f64() * 1e3);
    }
    put("connect_p50_ms", pct(&times, 0.50));
    put("connect_p95_ms", pct(&times, 0.95));

    eprintln!("[phase] rtt");
    // 2) RTT per payload size
    let mut scratch = Vec::new();
    for &size in &[64usize, 1024, 16384] {
        // warmup
        for _ in 0..3 {
            ping_rtt(&mut s, size, &mut scratch).await?;
        }
        let mut rtts = Vec::with_capacity(pings);
        for _ in 0..pings {
            rtts.push(ping_rtt(&mut s, size, &mut scratch).await?.as_secs_f64() * 1e3);
        }
        put(&format!("rtt{size}_p50_ms"), pct(&rtts, 0.50));
        put(&format!("rtt{size}_p95_ms"), pct(&rtts, 0.95));
        put(&format!("rtt{size}_p99_ms"), pct(&rtts, 0.99));
    }

    eprintln!("[phase] download");
    // 3) download throughput: BENCH total -> read DATA frames
    {
        let mut req = vec![0x02u8];
        req.extend_from_slice(&(dl_bytes as u32).to_be_bytes());
        write_frame(&mut s, &req).await?;
        let t = Instant::now();
        let mut got = 0usize;
        while got < dl_bytes {
            let f = read_frame(&mut s).await?;
            got += f.len() - 1;
        }
        let dt = t.elapsed();
        put("dl_mbps", dl_bytes as f64 / 1e6 / dt.as_secs_f64());
    }

    eprintln!("[phase] upload");
    // 3b) parallel download: dl_par connections share the transfer
    if dl_par > 1 {
        let per = dl_bytes / dl_par;
        let mut handles = Vec::new();
        let barrier = Arc::new(Barrier::new(dl_par));
        for _ in 0..dl_par {
            let socks = socks.to_string();
            let target = target.to_string();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                let mut c = socks_connect(&socks, &target).await?;
                let mut req = vec![0x02u8];
                req.extend_from_slice(&(per as u32).to_be_bytes());
                write_frame(&mut c, &req).await?;
                barrier.wait().await;
                let mut got = 0usize;
                while got < per {
                    let f = read_frame(&mut c).await?;
                    got += f.len() - 1;
                }
                Ok::<_, anyhow::Error>(())
            }));
        }
        let t = Instant::now();
        for h in handles {
            h.await??;
        }
        let dt = t.elapsed();
        put(&format!("dl{dl_par}par_mbps"), dl_bytes as f64 / 1e6 / dt.as_secs_f64());
    }

    // 4) upload throughput: SINK total + junk in one frame, wait for ACK
    {
        let mut head = vec![0x04u8];
        head.extend_from_slice(&(ul_bytes as u32).to_be_bytes());
        // frame payload = cmd + total + junk(ul_bytes)
        let plen: u32 = 1 + 4 + ul_bytes as u32;
        s.write_all(&plen.to_be_bytes()).await?;
        s.write_all(&head).await?;
        let junk = vec![0x42u8; CHUNK];
        let t = Instant::now();
        let mut sent = 0usize;
        while sent < ul_bytes {
            let n = junk.len().min(ul_bytes - sent);
            s.write_all(&junk[..n]).await?;
            sent += n;
        }
        s.flush().await?;
        let ack = read_frame(&mut s).await?;
        let dt = t.elapsed();
        if ack[0] != 0x05 {
            return Err(anyhow::anyhow!("bad ack"));
        }
        put("ul_mbps", ul_bytes as f64 / 1e6 / dt.as_secs_f64());
    }
    drop(s);

    eprintln!("[phase] concurrency");
    // 5) concurrency: conc_conns parallel proxied connections x conc_pings
    let barrier = Arc::new(Barrier::new(conc_conns));
    let mut handles = Vec::new();
    for _ in 0..conc_conns {
        let socks = socks.to_string();
        let target = target.to_string();
        let barrier = barrier.clone();
        handles.push(tokio::spawn(async move {
            let mut c = socks_connect(&socks, &target).await?;
            let mut scratch = vec![0u8; 64];
            scratch[0] = 0x01;
            barrier.wait().await;
            let mut rtts = Vec::with_capacity(conc_pings);
            for _ in 0..conc_pings {
                rtts.push(ping_rtt(&mut c, 64, &mut scratch).await?.as_secs_f64() * 1e3);
            }
            Ok::<_, anyhow::Error>(rtts)
        }));
    }
    let start = Instant::now();
    let mut all_rtts = Vec::new();
    for h in handles {
        all_rtts.extend(h.await??);
    }
    let wall = start.elapsed().as_secs_f64();
    let total_reqs = (conc_conns * conc_pings) as f64;
    put("conc_rps", total_reqs / wall);
    put("conc_p50_ms", pct(&all_rtts, 0.50));
    put("conc_p95_ms", pct(&all_rtts, 0.95));

    // -- output
    if pairs {
        for (k, v) in &metrics {
            println!("{k}={v:.3}");
        }
    } else {
        println!("{:<22} {:>12}", "metric", "value");
        for (k, v) in &metrics {
            println!("{:<22} {:>12.3}", k, v);
        }
    }
    Ok(())
}

fn pct(v: &[f64], p: f64) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((s.len() as f64 - 1.0) * p).round() as usize;
    s[idx.min(s.len() - 1)]
}
