use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, bail};
use futures::TryFutureExt;
use librqbit_core::hash_id::Id20;
use librqbit_dualstack_sockets::ConnectOpts;
use librqbit_utp::BindDevice;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tracing::debug;

use crate::{
    Error, PeerConnectionOptions, Result,
    mse::{self, EncryptionPolicy},
    network::{SocketFactory, UtpSocket},
    peer_connection::with_timeout,
    type_aliases::{BoxAsyncReadVectored, BoxAsyncWrite},
    vectored_traits::AsyncReadVectoredIntoCompat,
};

#[derive(Debug, Clone, Copy, Serialize)]
pub enum ConnectionKind {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "utp")]
    Utp,
    #[serde(rename = "socks")]
    Socks,
}

impl std::fmt::Display for ConnectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionKind::Tcp => f.write_str("tcp"),
            ConnectionKind::Utp => f.write_str("uTP"),
            ConnectionKind::Socks => f.write_str("socks"),
        }
    }
}

pub struct ConnectionOptions {
    // socks5://[username:password@]host:port
    // If set, all outgoing connections will go through the proxy over TCP.
    pub proxy_url: Option<String>,
    // TCP outgoing connections are enabled by default
    pub enable_tcp: bool,
    pub peer_opts: Option<PeerConnectionOptions>,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            enable_tcp: true,
            proxy_url: None,
            peer_opts: None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SocksProxyConfig {
    pub host: String,
    pub port: u16,
    pub username_password: Option<(String, String)>,
}

#[derive(Default, Debug, Clone)]
pub(crate) struct StreamConnectorArgs {
    pub enable_tcp: bool,
    pub socks_proxy_config: Option<SocksProxyConfig>,
    pub utp_socket: Option<UtpSocket>,
    pub bind_device: Option<BindDevice>,
    pub ipv4_only: bool,
    pub socket_factory: Option<Arc<dyn SocketFactory>>,
    pub encryption: EncryptionPolicy,
}

impl SocksProxyConfig {
    /// socks5h:// resolves hostnames via the proxy; socks5:// resolves them locally.
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        let url = ::url::Url::parse(url).context("invalid proxy URL")?;
        match url.scheme() {
            "socks5" | "socks5h" => {}
            other => anyhow::bail!("unsupported proxy URL scheme \"{other}\""),
        }
        let host = url.host_str().context("missing host")?;
        let port = url.port().context("missing port")?;
        let up = url
            .password()
            .map(|p| (url.username().to_owned(), p.to_owned()));
        Ok(Self {
            host: host.to_owned(),
            port,
            username_password: up,
        })
    }

    async fn connect(
        &self,
        addr: SocketAddr,
    ) -> tokio_socks::Result<(
        impl tokio::io::AsyncRead + Unpin + 'static,
        impl tokio::io::AsyncWrite + Unpin + 'static,
    )> {
        let proxy_addr = (self.host.as_str(), self.port);

        let stream = if let Some((username, password)) = self.username_password.as_ref() {
            tokio_socks::tcp::Socks5Stream::connect_with_password(
                proxy_addr,
                addr,
                username.as_str(),
                password.as_str(),
            )
            .await?
        } else {
            tokio_socks::tcp::Socks5Stream::connect(proxy_addr, addr).await?
        };

        Ok(tokio::io::split(stream))
    }
}

gen_stats!(SingleStatAtomic SingleStatSnapshot, [
    attempts u64,
    successes u64,
    errors u64
], []);
gen_stats!(PerFamilyAtomic PerFamilySnapshot, [], [
    v4 SingleStatAtomic SingleStatSnapshot,
    v6 SingleStatAtomic SingleStatSnapshot
]);
// Outgoing encrypted handshakes: how many were tried, how many ended in a
// fully encrypted or header-only stream, how many failed, and how many of
// those failures were retried in plaintext.
gen_stats!(EncryptionStatsAtomic EncryptionStatsSnapshot, [
    attempts u64,
    rc4 u64,
    header_only u64,
    failures u64,
    plaintext_fallbacks u64
], []);
gen_stats!(ConnectStatsAtomic ConnectStatsSnapshot, [], [
    socks PerFamilyAtomic PerFamilySnapshot,
    tcp PerFamilyAtomic PerFamilySnapshot,
    utp PerFamilyAtomic PerFamilySnapshot,
    encryption EncryptionStatsAtomic EncryptionStatsSnapshot
]);

/// An outgoing TCP connection: a kernel socket, or streams from a `SocketFactory`.
enum TcpConn {
    Kernel(tokio::net::TcpStream),
    Custom(BoxAsyncReadVectored, BoxAsyncWrite),
}

#[derive(Debug)]
pub(crate) struct StreamConnector {
    proxy_config: Option<SocksProxyConfig>,
    enable_tcp: bool,
    bind_device: Option<BindDevice>,
    utp_socket: Option<UtpSocket>,
    stats: ConnectStatsAtomic,
    ipv4_only: bool,
    socket_factory: Option<Arc<dyn SocketFactory>>,
    encryption: EncryptionPolicy,
}

impl StreamConnector {
    pub async fn new(config: StreamConnectorArgs) -> anyhow::Result<Self> {
        #[allow(clippy::single_match)]
        match (
            config.socks_proxy_config.is_some(),
            config.enable_tcp,
            config.utp_socket.is_some(),
        ) {
            (false, false, false) => {
                bail!("no way to connect to peers, enable TCP, uTP or socks proxy")
            }
            _ => {
                // TODO: maybe validate other combinations. For now there's no way to disable TCP
            }
        }

        Ok(Self {
            proxy_config: config.socks_proxy_config,
            enable_tcp: config.enable_tcp,
            utp_socket: config.utp_socket,
            bind_device: config.bind_device,
            stats: Default::default(),
            ipv4_only: config.ipv4_only,
            socket_factory: config.socket_factory,
            encryption: config.encryption,
        })
    }

    pub fn encryption(&self) -> EncryptionPolicy {
        self.encryption
    }

    /// Connect to a peer and send it our BitTorrent `handshake`, through the
    /// encrypted handshake when the policy asks for it. The returned halves
    /// carry the peer's reply.
    pub async fn connect_and_send_handshake(
        &self,
        addr: SocketAddr,
        info_hash: &Id20,
        handshake: &[u8],
        connect_timeout: Duration,
        rw_timeout: Duration,
    ) -> Result<(ConnectionKind, BoxAsyncReadVectored, BoxAsyncWrite)> {
        let connect = || with_timeout("connecting", connect_timeout, self.connect(addr));
        let send_plaintext = |kind, r, mut w: BoxAsyncWrite| async move {
            with_timeout(
                "writing",
                rw_timeout,
                w.write_all(handshake).map_err(Error::WriteHandshake),
            )
            .await?;
            Ok((kind, r, w))
        };

        if self.encryption == EncryptionPolicy::Disabled {
            let (kind, r, w) = connect().await?;
            return send_plaintext(kind, r, w).await;
        }

        let stats = &self.stats.encryption;
        let (kind, r, w) = connect().await?;
        stats.attempts(1);
        let offer = mse::outgoing_offer(self.encryption);
        let encrypted = with_timeout("encryption handshake", rw_timeout, async {
            Ok(mse::initiate(r, w, info_hash, offer, handshake).await?)
        })
        .await;
        let err = match encrypted {
            Ok(e) => {
                if e.method == mse::CRYPTO_RC4 {
                    stats.rc4(1);
                } else {
                    stats.header_only(1);
                }
                return Ok((kind, e.reader, e.writer));
            }
            Err(e) => e,
        };
        stats.failures(1);
        if self.encryption == EncryptionPolicy::Require {
            return Err(err);
        }
        debug!(
            ?addr,
            "encrypted handshake failed, retrying in plaintext: {err:#}"
        );
        stats.plaintext_fallbacks(1);
        let (kind, r, w) = connect().await?;
        send_plaintext(kind, r, w).await
    }

    fn get_stat(&self, kind: ConnectionKind, is_v6: bool) -> &SingleStatAtomic {
        let stat = match kind {
            ConnectionKind::Tcp => &self.stats.tcp,
            ConnectionKind::Utp => &self.stats.utp,
            ConnectionKind::Socks => &self.stats.socks,
        };
        if is_v6 { &stat.v6 } else { &stat.v4 }
    }

    async fn with_stat<R, E>(
        &self,
        kind: ConnectionKind,
        is_v6: bool,
        fut: impl Future<Output = std::result::Result<R, E>>,
    ) -> std::result::Result<R, E> {
        let stat = self.get_stat(kind, is_v6);
        stat.attempts(1);
        fut.await
            .inspect(|_| stat.successes(1))
            .inspect_err(|_| stat.errors(1))
    }

    async fn tcp_connect(
        &self,
        addr: SocketAddr,
    ) -> librqbit_dualstack_sockets::Result<tokio::net::TcpStream> {
        self.with_stat(
            ConnectionKind::Tcp,
            addr.is_ipv6(),
            librqbit_dualstack_sockets::tcp_connect(
                addr,
                ConnectOpts {
                    // Setting source port doesn't work with cloudflare warp on linux
                    // source_port: self.tcp_source_port,
                    source_port: None,
                    bind_device: self.bind_device.as_ref(),
                },
            ),
        )
        .await
    }

    pub fn stats(&self) -> &ConnectStatsAtomic {
        &self.stats
    }

    pub async fn connect(
        &self,
        addr: SocketAddr,
    ) -> Result<(ConnectionKind, BoxAsyncReadVectored, BoxAsyncWrite)> {
        if addr.port() == 0 {
            return Err(Error::Anyhow(anyhow::anyhow!(
                "invalid peer address (port 0): {}",
                addr
            )));
        }

        if self.ipv4_only && addr.is_ipv6() {
            return Err(Error::Anyhow(anyhow::anyhow!(
                "ipv6 disabled, skipping connection to {}",
                addr
            )));
        }

        if let Some(proxy) = self.proxy_config.as_ref() {
            let (r, w) = self
                .with_stat(ConnectionKind::Socks, addr.is_ipv6(), proxy.connect(addr))
                .await?;
            debug!(?addr, "connected through SOCKS5");
            return Ok((
                ConnectionKind::Socks,
                Box::new(r.into_vectored_compat()),
                Box::new(w),
            ));
        }

        // Try to connect over TCP first. If in 1 second we haven't connected, try uTP also (if configured).
        // Whoever connects first wins.
        let tcp_connect = async {
            if !self.enable_tcp {
                return Ok(None);
            }
            let conn = match self.socket_factory.as_ref() {
                Some(factory) => {
                    let (r, w) = self
                        .with_stat(
                            ConnectionKind::Tcp,
                            addr.is_ipv6(),
                            factory.connect_tcp(addr),
                        )
                        .await
                        .map_err(librqbit_dualstack_sockets::Error::Connect)?;
                    TcpConn::Custom(r, w)
                }
                None => TcpConn::Kernel(self.tcp_connect(addr).await?),
            };
            debug!(?addr, "connected over TCP");
            Ok::<_, librqbit_dualstack_sockets::Error>(Some(conn))
        };

        let tcp_failed_notify = tokio::sync::Notify::new();

        let utp_connect = async {
            let sock = match self.utp_socket.as_ref() {
                Some(sock) => sock,
                None => return Ok(None),
            };

            // Give TCP priority as it's more mature and simpler.
            if self.enable_tcp {
                // wait until either 1 second has passed or TCP failed.
                tokio::select! {
                    _ = tcp_failed_notify.notified() => {},
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }

            let conn = self
                .with_stat(ConnectionKind::Utp, addr.is_ipv6(), sock.connect(addr))
                .await?;

            debug!(?addr, "connected over uTP");
            Ok(Some(conn))
        };

        tokio::pin!(tcp_connect);
        tokio::pin!(utp_connect);

        let mut tcp_err: Option<Option<librqbit_dualstack_sockets::Error>> = None;
        let mut utp_err: Option<Option<librqbit_utp::Error>> = None;

        // wait until all fail, or one succeeds.
        loop {
            if let (Some(tcp), Some(utp)) = (tcp_err.as_mut(), utp_err.as_mut()) {
                match (tcp.take(), utp.take()) {
                    (Some(tcp), Some(utp)) => return Err(Error::Connect { tcp, utp }),
                    (Some(tcp), None) => return Err(Error::TcpConnect(tcp)),
                    (None, Some(utp)) => return Err(Error::UtpConnect(utp)),
                    (None, None) => return Err(Error::ConnectDisabled),
                }
            }
            tokio::select! {
                tcp_res = &mut tcp_connect, if tcp_err.is_none() => {
                    match tcp_res {
                        Ok(Some(TcpConn::Kernel(stream))) => {
                            let (r, w) = stream.into_split();
                            return Ok((ConnectionKind::Tcp, Box::new(r), Box::new(w)));
                        },
                        Ok(Some(TcpConn::Custom(r, w))) => {
                            return Ok((ConnectionKind::Tcp, r, w));
                        },
                        Ok(None) => {
                            tcp_err = Some(None);
                            tcp_failed_notify.notify_waiters();
                        }
                        Err(e) => {
                            tcp_err = Some(Some(e));
                            tcp_failed_notify.notify_waiters();
                        }
                    }
                },
                utp_res = &mut utp_connect, if utp_err.is_none() => {
                    match utp_res {
                        Ok(Some(stream)) => {
                            let (r, w) = stream.split();
                            return Ok((ConnectionKind::Utp, Box::new(r), Box::new(w)));
                        },
                        Ok(None) => {
                            utp_err = Some(None);
                        }
                        Err(e) => {
                            utp_err = Some(Some(e));
                        }
                    }
                },
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socks5() {
        let c = SocksProxyConfig::parse("socks5://myhost:1234").unwrap();
        assert_eq!(c.host, "myhost");
        assert_eq!(c.port, 1234);
        assert_eq!(c.username_password, None);
    }

    #[test]
    fn test_parse_socks5h() {
        let c = SocksProxyConfig::parse("socks5h://myhost:1234").unwrap();
        assert_eq!(c.host, "myhost");
        assert_eq!(c.port, 1234);
    }

    #[test]
    fn test_parse_with_password() {
        let c = SocksProxyConfig::parse("socks5h://user:pass@myhost:1234").unwrap();
        assert_eq!(c.host, "myhost");
        assert_eq!(c.port, 1234);
        assert_eq!(
            c.username_password,
            Some(("user".to_owned(), "pass".to_owned()))
        );
    }

    #[test]
    fn test_parse_rejects_other_schemes() {
        for url in [
            "http://myhost:1234",
            "socks4://myhost:1234",
            "socks4a://myhost:1234",
        ] {
            assert!(SocksProxyConfig::parse(url).is_err(), "should reject {url}");
        }
    }

    #[test]
    fn test_parse_rejects_garbage() {
        assert!(SocksProxyConfig::parse("not a url").is_err());
        assert!(SocksProxyConfig::parse("socks5://").is_err());
    }
}
