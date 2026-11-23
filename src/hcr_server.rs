use getrandom::getrandom;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Notify};

const HEADER_LEN: usize = 62;
const RESP_HEADER_LEN: usize = 14;

fn obfuscate(data: &mut [u8], key: &[u8; 16], op: u8, seq: u64, dirflag: u8) {
    let mut i = 0;
    let d = dirflag ^ 1;
    while i < data.len() {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(&[op]);
        hasher.update(seq.to_be_bytes());
        hasher.update(&[d]);
        hasher.update(((i / 32) as u32).to_be_bytes());
        let ks = hasher.finalize();

        let chunk_len = std::cmp::min(32, data.len() - i);
        for j in 0..chunk_len {
            data[i + j] ^= ks[j];
        }
        i += 32;
    }
}

struct Session {
    id: [u8; 16],
    token: [u8; 32],
    upload_tx: mpsc::Sender<Vec<u8>>,
    downloads: Mutex<BTreeMap<u64, Vec<u8>>>,
    next_dl_seq: AtomicU64,
    dl_notify: Notify,
}

struct Server {
    sessions: Mutex<HashMap<[u8; 16], Arc<Session>>>,
    target: String,
}

pub async fn start(listen_addr: &str, target_addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    println!("[HCR] Servidor nativo integrado iniciado em {}", listen_addr);
    let server = Arc::new(Server {
        sessions: Mutex::new(HashMap::new()),
        target: target_addr.to_string(),
    });

    loop {
        if let Ok((stream, _)) = listener.accept().await {
            let srv = server.clone();
            tokio::spawn(async move {
                let _ = handle_connection(stream, srv).await;
            });
        }
    }
}

async fn send_resp(
    stream: &mut TcpStream,
    status: u8,
    seq: u64,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut header = [0u8; RESP_HEADER_LEN];
    header[0] = status;
    header[1] = 1;
    header[2..10].copy_from_slice(&seq.to_be_bytes());
    header[10..14].copy_from_slice(&(payload.len() as u32).to_be_bytes());

    stream.write_all(&header).await?;
    if !payload.is_empty() {
        stream.write_all(payload).await?;
    }
    Ok(())
}

async fn handle_connection(mut stream: TcpStream, server: Arc<Server>) -> std::io::Result<()> {
    let mut header = [0u8; HEADER_LEN];
    if stream.read_exact(&mut header).await.is_err() {
        return Ok(());
    }

    let op = header[0];
    let ver = header[1];
    if ver != 1 {
        return Ok(());
    }

    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&header[2..18]);

    let seq = u64::from_be_bytes(header[50..58].try_into().unwrap());
    let len = u32::from_be_bytes(header[58..62].try_into().unwrap()) as usize;

    if len > 262144 {
        return Ok(());
    }

    let mut payload = vec![0u8; len];
    if len > 0 {
        if stream.read_exact(&mut payload).await.is_err() {
            return Ok(());
        }
    }

    match op {
        1 => {
            let mut tok = [0u8; 32];
            let _ = getrandom(&mut tok);
            let (tx, mut rx) = mpsc::channel(1024);

            let sess = Arc::new(Session {
                id: session_id,
                token: tok,
                upload_tx: tx,
                downloads: Mutex::new(BTreeMap::new()),
                next_dl_seq: AtomicU64::new(0),
                dl_notify: Notify::new(),
            });

            server.sessions.lock().await.insert(session_id, sess.clone());

            let target = server.target.clone();
            tokio::spawn(async move {
                if let Ok(mut ssh) = TcpStream::connect(&target).await {
                    let (mut ssh_rx, mut ssh_tx) = ssh.into_split();
                    let sess_clone = sess.clone();

                    let t1 = tokio::spawn(async move {
                        let mut buf = [0u8; 16384];
                        loop {
                            match ssh_rx.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    let mut frame = Vec::with_capacity(4 + n);
                                    frame.extend_from_slice(&(n as u32).to_be_bytes());
                                    frame.extend_from_slice(&buf[..n]);

                                    let sq = sess_clone.next_dl_seq.fetch_add(1, Ordering::SeqCst);
                                    sess_clone.downloads.lock().await.insert(sq, frame);
                                    sess_clone.dl_notify.notify_waiters();
                                }
                            }
                        }
                    });

                    let t2 = tokio::spawn(async move {
                        while let Some(data) = rx.recv().await {
                            if ssh_tx.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                    });

                    let _ = tokio::join!(t1, t2);
                }
            });

            let mut out_payload = tok.to_vec();
            obfuscate(&mut out_payload, &session_id, op, seq, 1);
            send_resp(&mut stream, 0, seq, &out_payload).await?;
        }
        2 => {
            let sess = server.sessions.lock().await.get(&session_id).cloned();
            if let Some(sess) = sess {
                obfuscate(&mut payload, &session_id, op, seq, 0);
                let _ = sess.upload_tx.send(payload).await;
                send_resp(&mut stream, 0, seq + 1, &[]).await?;
            } else {
                let mut out = b"AUTH_FAILED".to_vec();
                obfuscate(&mut out, &session_id, op, seq, 1);
                send_resp(&mut stream, 4, seq, &out).await?;
            }
        }
        3 => {
            let sess = server.sessions.lock().await.get(&session_id).cloned();
            if let Some(sess) = sess {
                let mut wait_time = 0;
                let chunk = loop {
                    let mut dl = sess.downloads.lock().await;
                    if let Some(c) = dl.get(&seq) {
                        break Some(c.clone());
                    }
                    drop(dl);
                    if wait_time > 24 {
                        break None;
                    }
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), sess.dl_notify.notified()).await;
                    wait_time += 1;
                };

                if let Some(mut c) = chunk {
                    obfuscate(&mut c, &session_id, op, seq, 1);
                    send_resp(&mut stream, 1, seq, &c).await?;
                } else {
                    send_resp(&mut stream, 2, seq, &[]).await?;
                }
            } else {
                let mut out = b"AUTH_FAILED".to_vec();
                obfuscate(&mut out, &session_id, op, seq, 1);
                send_resp(&mut stream, 4, seq, &out).await?;
            }
        }
        4 => {
            let sess = server.sessions.lock().await.get(&session_id).cloned();
            if let Some(sess) = sess {
                let mut dl = sess.downloads.lock().await;
                let mut to_remove = Vec::new();
                for &k in dl.keys() {
                    if k <= seq {
                        to_remove.push(k);
                    } else {
                        break;
                    }
                }
                for k in to_remove {
                    dl.remove(&k);
                }
                send_resp(&mut stream, 0, seq, &[]).await?;
            }
        }
        5 => {
            server.sessions.lock().await.remove(&session_id);
            send_resp(&mut stream, 3, seq, &[]).await?;
        }
        6 => {
            let sess = server.sessions.lock().await.get(&session_id).cloned();
            if sess.is_some() {
                send_resp(&mut stream, 0, seq, &[]).await?;
            } else {
                let mut out = b"AUTH_FAILED".to_vec();
                obfuscate(&mut out, &session_id, op, seq, 1);
                send_resp(&mut stream, 4, seq, &out).await?;
            }
        }
        _ => {
            let mut out = b"INVALID_REQUEST".to_vec();
            obfuscate(&mut out, &session_id, op, seq, 1);
            send_resp(&mut stream, 4, seq, &out).await?;
        }
    }
    Ok(())
}
