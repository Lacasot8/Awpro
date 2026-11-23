use crate::hcr::{
    HEADER_LEN as HCR_HEADER_SIZE, MAX_PAYLOAD as HCR_MAX_PAYLOAD, VERSION as HCR_VERSION,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha1::{Digest, Sha1};
use std::io;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout, Duration};

const MAX_PEEK: usize = 16 * 1024;
const DETECT_TIMEOUT: Duration = Duration::from_millis(800);
const HCR_FIRST_BYTE_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Socks4,
    Socks5,
    Hcr,
    Tls,
    WebSocket,
    Security,
    Http,
    SshDirect,
    Unknown,
}

/// Classifica somente handshakes reconhecidos. Nenhum byte é consumido.
pub fn detect_protocol(data: &[u8]) -> Option<Protocol> {
    if data.is_empty() {
        return None;
    }

    match sniff_hcr_frame(data) {
        Some(true) => return Some(Protocol::Hcr),
        None => return None,
        _ => {}
    }

    if data[0] == 0x04 {
        return Some(Protocol::Socks4);
    }
    if data[0] == 0x05 {
        return Some(Protocol::Socks5);
    }
    if data[0] == 0x16 {
        return Some(Protocol::Tls);
    }
    if starts_with_ascii_case_insensitive(data, b"SECURITY")
        || starts_with_ascii_case_insensitive(data, b"AUTH")
    {
        return Some(Protocol::Security);
    }
    if data.starts_with(b"SSH-") {
        return Some(Protocol::SshDirect);
    }

    if is_http_method_prefix(data) {
        let request = String::from_utf8_lossy(data);
        let Some(header_end) = request.find("\r\n\r\n") else {
            return None;
        };
        let headers = &request[..header_end];
        let security_upgrade = header_value(headers, "Upgrade").is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("security"))
        });
        let security_protocol = header_value(headers, "X-Protocol")
            .is_some_and(|value| value.eq_ignore_ascii_case("security"));
        if security_upgrade || security_protocol {
            return Some(Protocol::Security);
        }
        if is_valid_websocket_upgrade(headers) {
            return Some(Protocol::WebSocket);
        }
        return Some(Protocol::Http);
    }

    None
}

/// Reconhece Expect: 100-continue e variantes usadas por payloads customizados.
pub fn has_expect_continue(data: &[u8]) -> bool {
    String::from_utf8_lossy(data).lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("expect")
            && value.to_ascii_lowercase().contains("continue")
    })
}

/// Aguarda um prefixo suficiente para classificação, usando peek para preservar
/// o handshake para o respectivo handler. Conexões silenciosas são classificadas
/// como SSH_DIRECT para que o dispatcher aplique a política da porta.
pub async fn detect_from_stream(stream: &TcpStream) -> io::Result<Protocol> {
    let mut buffer = vec![0u8; MAX_PEEK];
    let mut bytes_peeked = 0usize;

    let result = timeout(DETECT_TIMEOUT, async {
        loop {
            bytes_peeked = stream.peek(&mut buffer).await?;
            if bytes_peeked == 0 {
                return Ok(Protocol::SshDirect);
            }

            if let Some(protocol) = detect_protocol(&buffer[..bytes_peeked]) {
                return Ok(protocol);
            }

            if bytes_peeked >= MAX_PEEK {
                return Ok(if is_incomplete_http_message(&buffer[..bytes_peeked]) {
                    Protocol::Http
                } else {
                    Protocol::Unknown
                });
            }

            if is_http_method_prefix(&buffer[..bytes_peeked]) {
                sleep(Duration::from_millis(10)).await;
                continue;
            }
            if !may_be_incomplete_known_prefix(&buffer[..bytes_peeked]) {
                return Ok(Protocol::Unknown);
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;

    match result {
        Ok(classification) => classification,
        Err(_) if bytes_peeked == 0 => Ok(Protocol::SshDirect),
        Err(_) => {
            let data = &buffer[..bytes_peeked];
            if let Some(protocol) = classify_after_protocol_timeout(data) {
                Ok(protocol)
            } else if is_incomplete_http_message(data) {
                Ok(Protocol::Http)
            } else {
                Ok(Protocol::Unknown)
            }
        }
    }
}

/// Detecta HCR sem bloquear o handshake HTTP da opção 1. O HTTP Injector
/// espera o primeiro `101` do servidor antes de enviar o payload; por isso há
/// uma janela curta para o primeiro byte HCR. Se nenhum byte chegar nessa
/// janela, a conexão segue imediatamente para o protocolo normal da porta.
/// Depois de reconhecer um prefixo HCR válido, aguardamos o cabeçalho completo
/// para aceitar fragmentação em redes móveis.
pub async fn detect_hcr_only(stream: &TcpStream) -> io::Result<bool> {
    Ok(matches!(detect_hcr(stream).await?, HcrMatch::Raw))
}

/// Resultado da detecção HCR da opção H.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HcrMatch {
    /// Não é HCR; a conexão segue o modo normal da porta.
    None,
    /// Frame HCR binário direto (ex.: porta 8880 sem proxy da operadora).
    Raw,
    /// HCR encapsulado em `GET /hcr` + `Upgrade: websocket`. O cabeçalho HTTP
    /// tem `header_len` bytes e deve ser consumido antes do relay; `response`
    /// é o `101` que precisa ser enviado ao cliente.
    HttpUpgrade { header_len: usize, response: Vec<u8> },
}

/// Detecta HCR cru ou HCR por HTTP Upgrade sem consumir bytes. Proxies
/// transparentes de operadoras nas portas 80/8080 costumam derrubar tráfego
/// binário; por isso o APK corrigido abre cada conexão HCR com um handshake
/// HTTP marcado (`/hcr` ou `X-AzPro-HCR`) e só depois envia os frames.
pub async fn detect_hcr(stream: &TcpStream) -> io::Result<HcrMatch> {
    let mut buffer = [0u8; HCR_HEADER_SIZE];
    let first_byte = match timeout(HCR_FIRST_BYTE_TIMEOUT, stream.peek(&mut buffer[..1])).await {
        Ok(Ok(bytes)) if bytes > 0 => buffer[0],
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => return Ok(HcrMatch::None),
    };
    if first_byte.is_ascii_alphabetic() {
        return detect_hcr_http_upgrade(stream).await;
    }
    if !(1..=6).contains(&first_byte) {
        return Ok(HcrMatch::None);
    }
    // Só os opcodes HCR entram na espera fragmentada. HTTP, TLS e SSH não
    // passam por este caminho e preservam o tempo de resposta da opção 1.
    let result = timeout(Duration::from_secs(8), async {
        loop {
            let bytes_peeked = stream.peek(&mut buffer).await?;
            if bytes_peeked == 0 {
                return Ok(false);
            }
            match sniff_hcr_frame(&buffer[..bytes_peeked]) {
                Some(true) => return Ok(true),
                Some(false) => return Ok(false),
                None => sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await;
    match result {
        Ok(Ok(true)) => Ok(HcrMatch::Raw),
        Ok(Ok(false)) | Err(_) => Ok(HcrMatch::None),
        Ok(Err(error)) => Err(error),
    }
}

const HCR_HTTP_MAX_HEADER: usize = 8 * 1024;
const HCR_HTTP_HEADER_TIMEOUT: Duration = Duration::from_secs(3);
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

async fn detect_hcr_http_upgrade(stream: &TcpStream) -> io::Result<HcrMatch> {
    let mut buffer = vec![0u8; HCR_HTTP_MAX_HEADER];
    let result = timeout(HCR_HTTP_HEADER_TIMEOUT, async {
        loop {
            let peeked = stream.peek(&mut buffer).await?;
            if peeked == 0 {
                return Ok(HcrMatch::None);
            }
            let data = &buffer[..peeked];
            if !is_http_method_prefix(data) {
                return Ok(HcrMatch::None);
            }
            if let Some(end) = find_header_end(data) {
                return Ok(classify_hcr_http_request(&data[..end]));
            }
            if peeked >= HCR_HTTP_MAX_HEADER {
                return Ok(HcrMatch::None);
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    match result {
        Ok(value) => value,
        Err(_) => Ok(HcrMatch::None),
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

/// Reconhece somente pedidos HCR marcados; qualquer outro HTTP (payloads do
/// HTTP Injector, WebSocket SSH etc.) continua no fluxo normal da porta.
fn classify_hcr_http_request(header: &[u8]) -> HcrMatch {
    let Ok(text) = std::str::from_utf8(header) else {
        return HcrMatch::None;
    };
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let _method = parts.next();
    let target = parts.next().unwrap_or_default();
    let path = target
        .split_once("://")
        .map(|(_, rest)| rest.find('/').map_or("/", |index| &rest[index..]))
        .unwrap_or(target);
    let path_marker = path.len() >= 4
        && path[..4].eq_ignore_ascii_case("/hcr")
        && matches!(path.as_bytes().get(4), None | Some(b'/') | Some(b'?'));
    let mut header_marker = false;
    let mut websocket_key = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("X-AzPro-HCR") {
            header_marker = true;
        } else if name.eq_ignore_ascii_case("Sec-WebSocket-Key") {
            websocket_key = Some(value.trim().to_string());
        }
    }
    if !path_marker && !header_marker {
        return HcrMatch::None;
    }
    let mut response = String::from(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",
    );
    if let Some(key) = websocket_key.filter(|key| !key.is_empty()) {
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(WEBSOCKET_GUID.as_bytes());
        response.push_str(&format!(
            "Sec-WebSocket-Accept: {}\r\n",
            STANDARD.encode(hasher.finalize())
        ));
    }
    response.push_str("\r\n");
    HcrMatch::HttpUpgrade {
        header_len: header.len(),
        response: response.into_bytes(),
    }
}

fn is_http_method_prefix(data: &[u8]) -> bool {
    const RESPONSE_PREFIX: &[u8] = b"HTTP/";
    if data.len() <= RESPONSE_PREFIX.len()
        && RESPONSE_PREFIX[..data.len()].eq_ignore_ascii_case(data)
    {
        return true;
    }
    if data.len() > RESPONSE_PREFIX.len()
        && data[..RESPONSE_PREFIX.len()].eq_ignore_ascii_case(RESPONSE_PREFIX)
    {
        return true;
    }

    let method_end = data
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(data.len());
    let method = &data[..method_end];
    if method.is_empty() || method.len() > 32 || !method.iter().all(|byte| is_http_token(*byte)) {
        return false;
    }

    // Antes do espaço, pode ser um método dividido entre pacotes; depois dele,
    // a linha continua sendo tratada como HTTP até a detecção dos headers.
    true
}

fn is_incomplete_http_message(data: &[u8]) -> bool {
    if data.starts_with(b"HTTP/") {
        return true;
    }
    let Some(space) = data.iter().position(|byte| *byte == b' ') else {
        return false;
    };
    let method = &data[..space];
    let target = &data[space + 1..];
    !method.is_empty()
        && method.len() <= 32
        && method.iter().all(|byte| is_http_token(*byte))
        && target.iter().any(|byte| !byte.is_ascii_whitespace())
}

fn is_http_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// `Some(true)` is a valid HCR header, `Some(false)` cannot be HCR, and `None`
/// means the bytes still match an HCR prefix and more are needed. Any of the six
/// HCR request opcodes may arrive on a separate TCP connection, so inspect all
/// of them before SOCKS4/SOCKS5, whose first bytes overlap with HCR opcodes 4/5.
fn sniff_hcr_frame(data: &[u8]) -> Option<bool> {
    if data.is_empty() {
        return None;
    }
    if !(1..=6).contains(&data[0]) {
        return Some(false);
    }
    if data.len() < 2 {
        return None;
    }
    if data[1] != HCR_VERSION {
        return Some(false);
    }
    if data.len() < HCR_HEADER_SIZE {
        return None;
    }
    let payload_len = u32::from_be_bytes([data[58], data[59], data[60], data[61]]);
    Some((payload_len as usize) <= HCR_MAX_PAYLOAD)
}

fn is_socks4_prefix(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x04 && matches!(data[1], 0x01 | 0x02)
}

fn is_complete_socks4_request(data: &[u8]) -> bool {
    is_socks4_prefix(data) && data.len() >= 9 && data[8..].contains(&0)
}

fn is_complete_socks5_greeting(data: &[u8]) -> bool {
    data.len() >= 2
        && data[0] == 0x05
        && data[1] > 0
        && data.len() >= 2 + usize::from(data[1])
}

fn classify_after_protocol_timeout(data: &[u8]) -> Option<Protocol> {
    if is_complete_socks4_request(data) {
        Some(Protocol::Socks4)
    } else if is_complete_socks5_greeting(data) {
        Some(Protocol::Socks5)
    } else {
        None
    }
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn header_has_token(headers: &str, name: &str, token: &str) -> bool {
    headers.lines().skip(1).any(|line| {
        let Some((key, value)) = line.split_once(':') else {
            return false;
        };
        key.trim().eq_ignore_ascii_case(name)
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
    })
}

fn is_valid_websocket_upgrade(headers: &str) -> bool {
    let mut lines = headers.lines();
    let Some(start_line) = lines.next() else {
        return false;
    };
    let fields: Vec<_> = start_line.split_ascii_whitespace().collect();
    if fields.len() != 3 || fields[0] != "GET" || fields[2] != "HTTP/1.1" {
        return false;
    }
    if !header_has_token(headers, "Upgrade", "websocket")
        || !header_has_token(headers, "Connection", "upgrade")
        || header_value(headers, "Sec-WebSocket-Version") != Some("13")
    {
        return false;
    }
    header_value(headers, "Sec-WebSocket-Key")
        .and_then(|key| STANDARD.decode(key).ok())
        .is_some_and(|decoded| decoded.len() == 16)
}

fn may_be_incomplete_known_prefix(data: &[u8]) -> bool {
    if sniff_hcr_frame(data).is_none() {
        return true;
    }
    const PREFIXES: [&[u8]; 13] = [
        b"SSH-",
        b"SECURITY",
        b"AUTH",
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"PATCH ",
        b"HEAD ",
        b"CONNECT ",
        b"OPTIONS ",
        b"TRACE ",
        b"HTTP/",
    ];
    PREFIXES
        .iter()
        .any(|prefix| data.len() < prefix.len() && prefix[..data.len()].eq_ignore_ascii_case(data))
}

fn starts_with_ascii_case_insensitive(data: &[u8], prefix: &[u8]) -> bool {
    data.len() >= prefix.len() && prefix.eq_ignore_ascii_case(&data[..prefix.len()])
}

#[cfg(test)]
mod tests {
    use super::{
        classify_after_protocol_timeout, classify_hcr_http_request, detect_hcr, detect_hcr_only,
        detect_protocol, has_expect_continue, is_incomplete_http_message, HcrMatch, Protocol,
        HCR_HEADER_SIZE, HCR_MAX_PAYLOAD,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{sleep, Duration};

    #[test]
    fn detects_binary_and_raw_protocol_signatures() {
        let socks4 = b"\x04\x01\x00\x50\x7f\x00\x00\x01user\x00";
        let socks5 = b"\x05\x01\x00";
        assert_eq!(detect_protocol(socks4), None);
        assert_eq!(detect_protocol(socks5), None);
        assert_eq!(classify_after_protocol_timeout(socks4), Some(Protocol::Socks4));
        assert_eq!(classify_after_protocol_timeout(socks5), Some(Protocol::Socks5));
        assert_eq!(detect_protocol(&[0x16, 0x03, 0x01]), Some(Protocol::Tls));
        assert_eq!(
            detect_protocol(b"SSH-2.0-client\r\n"),
            Some(Protocol::SshDirect)
        );
        assert_eq!(detect_protocol(b"SECURITY /\r\n"), Some(Protocol::Security));
        assert_eq!(detect_protocol(b"AUTH payload"), Some(Protocol::Security));
    }

    #[test]
    fn detects_all_complete_hcr_opcodes_before_overlapping_protocols() {
        let mut hcr = [0u8; HCR_HEADER_SIZE];
        hcr[1] = 1; // HCR protocol version
        for opcode in 1..=6 {
            hcr[0] = opcode;
            assert_eq!(detect_protocol(&hcr), Some(Protocol::Hcr));
        }
        hcr[0] = 1;
        assert_eq!(detect_protocol(&hcr[..2]), None);

        hcr[58..62].copy_from_slice(&((HCR_MAX_PAYLOAD as u32) + 1).to_be_bytes());
        assert_eq!(detect_protocol(&hcr), None);
    }

    #[tokio::test]
    async fn detects_fragmented_hcr_header_without_consuming_request_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let mut header = [0u8; HCR_HEADER_SIZE];
        header[0] = 5; // Também coincide com o primeiro byte de um handshake SOCKS5.
        header[1] = 1;
        let writer = tokio::spawn(async move {
            client.write_all(&header[..7]).await.unwrap();
            sleep(Duration::from_millis(25)).await;
            client.write_all(&header[7..]).await.unwrap();
            header
        });

        assert!(detect_hcr_only(&server).await.unwrap());
        let header = writer.await.unwrap();
        let mut peeked = [0u8; HCR_HEADER_SIZE];
        assert_eq!(server.peek(&mut peeked).await.unwrap(), HCR_HEADER_SIZE);
        assert_eq!(peeked, header);
    }

    #[test]
    fn distinguishes_websocket_security_and_http_after_complete_headers() {
        let websocket = b"GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        let security = b"GET / HTTP/1.1\r\nUpgrade: security\r\nConnection: Upgrade\r\n\r\n";
        let http = b"CONNECT host:22 HTTP/1.1\r\nHost: host:22\r\n\r\n";
        assert_eq!(detect_protocol(websocket), Some(Protocol::WebSocket));
        assert_eq!(detect_protocol(security), Some(Protocol::Security));
        assert_eq!(detect_protocol(http), Some(Protocol::Http));
    }

    #[test]
    fn does_not_misclassify_http_when_security_text_appears_in_an_unrelated_header() {
        let http = b"GET / HTTP/1.1\r\nHost: example\r\nUser-Agent: note Upgrade: security\r\n\r\n";
        assert_eq!(detect_protocol(http), Some(Protocol::Http));
    }

    #[test]
    fn only_first_http_header_block_controls_dispatch() {
        let pipelined = b"GET / HTTP/1.1\r\nHost: example\r\n\r\nGET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        let incomplete_upgrade =
            b"GET / HTTP/1.1\r\nHost: example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert_eq!(detect_protocol(pipelined), Some(Protocol::Http));
        assert_eq!(detect_protocol(incomplete_upgrade), Some(Protocol::Http));
    }

    #[test]
    fn waits_for_partial_http_headers() {
        assert_eq!(detect_protocol(b"GET / HTTP/1.1\r\nHost: ex"), None);
    }

    #[test]
    fn detects_extension_http_methods_but_rejects_non_token_lines() {
        let propfind = b"PROPFIND /dav HTTP/1.1\r\nHost: example\r\n\r\n";
        let m_search = b"M-SEARCH * HTTP/1.1\r\nHost: example\r\n\r\n";
        assert_eq!(detect_protocol(propfind), Some(Protocol::Http));
        assert_eq!(detect_protocol(m_search), Some(Protocol::Http));
        assert_eq!(detect_protocol(b"?? / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn incomplete_http_fallback_rejects_arbitrary_unknown_text() {
        assert!(!is_incomplete_http_message(b"xyz"));
        assert!(!is_incomplete_http_message(b"SSH-2.0-test"));
        assert!(is_incomplete_http_message(b"GET /"));
        assert!(is_incomplete_http_message(b"UPDATE [host]"));
        assert!(is_incomplete_http_message(b"HTTP/1.1 200"));
    }

    #[test]
    fn detects_continue_expect_header_case_insensitively() {
        assert!(has_expect_continue(
            b"GET / HTTP/1.1\r\nExpect: 101-continue\r\n\r\n"
        ));
        assert!(has_expect_continue(
            b"POST / HTTP/1.1\nexpect: 100-Continue\n\n"
        ));
        assert!(!has_expect_continue(
            b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"
        ));
    }

    #[test]
    fn recognizes_marked_hcr_http_upgrade_only() {
        let request = b"GET /hcr HTTP/1.1\r\nHost: vps\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        match classify_hcr_http_request(request) {
            HcrMatch::HttpUpgrade { header_len, response } => {
                assert_eq!(header_len, request.len());
                let response = String::from_utf8(response).unwrap();
                assert!(response.starts_with("HTTP/1.1 101 "));
                assert!(response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
                assert!(response.ends_with("\r\n\r\n"));
            }
            other => panic!("esperava upgrade HCR, obtido {other:?}"),
        }
        let header = b"GET / HTTP/1.1\r\nHost: vps\r\nX-AzPro-HCR: 1\r\n\r\n";
        assert!(matches!(classify_hcr_http_request(header), HcrMatch::HttpUpgrade { .. }));
        let absolute = b"GET http://vps/hcr?x=1 HTTP/1.1\r\nHost: vps\r\n\r\n";
        assert!(matches!(classify_hcr_http_request(absolute), HcrMatch::HttpUpgrade { .. }));
        let websocket_ssh = b"GET / HTTP/1.1\r\nHost: vps\r\nUpgrade: websocket\r\n\r\n";
        assert_eq!(classify_hcr_http_request(websocket_ssh), HcrMatch::None);
        let other_path = b"GET /hcrx HTTP/1.1\r\nHost: vps\r\n\r\n";
        assert_eq!(classify_hcr_http_request(other_path), HcrMatch::None);
    }

    #[tokio::test]
    async fn detects_fragmented_hcr_http_upgrade_without_consuming_frames() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let request = b"GET /hcr HTTP/1.1\r\nHost: vps\r\nUpgrade: websocket\r\n\r\n".to_vec();
        let expected_len = request.len();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(&request[..10]).await.unwrap();
            sleep(Duration::from_millis(50)).await;
            stream.write_all(&request[10..]).await.unwrap();
            stream.write_all(&[1u8, 1u8]).await.unwrap();
            sleep(Duration::from_millis(200)).await;
        });
        let (server, _) = listener.accept().await.unwrap();
        match detect_hcr(&server).await.unwrap() {
            HcrMatch::HttpUpgrade { header_len, .. } => assert_eq!(header_len, expected_len),
            other => panic!("esperava upgrade HCR, obtido {other:?}"),
        }
        let mut peek = vec![0u8; expected_len + 2];
        let peeked = server.peek(&mut peek).await.unwrap();
        assert_eq!(&peek[..3], b"GET");
        assert!(peeked >= expected_len);
        client.await.unwrap();
    }
}
