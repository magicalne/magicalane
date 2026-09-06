//! httpfetch: GET over a plain TCP stream (content-length + chunked).

use lib::httpfetch;

async fn spawn_http(resp: Vec<u8>) -> std::io::Result<std::net::SocketAddr> {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = l.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(&resp).await;
            let _ = s.shutdown().await;
        }
    });
    Ok(addr)
}

#[tokio::test]
async fn get_with_content_length() {
    let body = b"hello-provider\n";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let full = format!("{resp}{}", String::from_utf8_lossy(body));
    let addr = spawn_http(full.into_bytes()).await.unwrap();
    let url_str = format!("http://{addr}/list.txt");
    let url = httpfetch::parse_url(&url_str).unwrap();
    let s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let got = httpfetch::fetch_over(s, &url).await.unwrap();
    assert_eq!(got, body);
}

#[tokio::test]
async fn get_chunked() {
    let resp: Vec<u8> =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n-provi\r\n3\r\nder\r\n0\r\n\r\n"
        .to_vec();
    let addr = spawn_http(resp).await.unwrap();
    let url_str = format!("http://{addr}/c.txt");
    let url = httpfetch::parse_url(&url_str).unwrap();
    let s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let got = httpfetch::fetch_over(s, &url).await.unwrap();
    assert_eq!(got, b"hello-provider");
}

#[tokio::test]
async fn get_close_delimited() {
    let resp: Vec<u8> = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nraw-body-no-length".to_vec();
    let addr = spawn_http(resp).await.unwrap();
    let url_str = format!("http://{addr}/x");
    let url = httpfetch::parse_url(&url_str).unwrap();
    let s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let got = httpfetch::fetch_over(s, &url).await.unwrap();
    assert_eq!(got, b"raw-body-no-length");
}

#[test]
fn url_parsing() {
    let u = httpfetch::parse_url("https://example.com/a/b.txt").unwrap();
    assert!(u.tls && u.port == 443 && u.path == "/a/b.txt" && u.host == "example.com");
    let u = httpfetch::parse_url("http://127.0.0.1:8082/list.txt").unwrap();
    assert!(!u.tls && u.port == 8082 && u.host == "127.0.0.1" && u.path == "/list.txt");
    assert!(httpfetch::parse_url("ftp://x/").is_err());
}
