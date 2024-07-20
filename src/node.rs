use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::Context;
use parking_lot::RwLock;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync,
};
use tokio_rustls::{rustls::pki_types::ServerName, TlsConnector};

use crate::x509::X509;

type ReadChannelSend = sync::mpsc::UnboundedSender<Arc<Vec<u8>>>;
type ReadChannelRecv = sync::mpsc::UnboundedReceiver<Arc<Vec<u8>>>;
type Connections = Arc<RwLock<HashMap<SocketAddr, sync::mpsc::UnboundedSender<NodeInnerMsg>>>>;

#[derive(Clone)]
pub struct TlsNode {
    connector: Arc<TlsConnector>,
    connections: Connections,
}

impl TlsNode {
    pub fn new(x509: X509) -> anyhow::Result<Self> {
        let config = Arc::new(x509.try_into()?);
        let connector = TlsConnector::from(config);

        Ok(Self {
            connector: Arc::new(connector),
            connections: Arc::default(),
        })
    }

    pub async fn connect_with_handshake(&self, addr: SocketAddr) -> anyhow::Result<()> {
        {
            let conns = self.connections.read();

            if conns.contains_key(&addr) {
                tracing::warn!("the connection has already been established!");
                return Ok(());
            }
        }

        let connector = Arc::clone(&self.connector);
        let (tx, mut rx) = sync::mpsc::unbounded_channel::<NodeInnerMsg>();
        let (handshake_tx, handshake_rx) = sync::oneshot::channel::<()>();

        let connection_loop = async move {
            let stream = TcpStream::connect(&addr).await?;
            let domain = ServerName::try_from("localhost")?;

            let tls_stream = connector
                .connect(domain, stream)
                .await
                .context("tls connection")?;

            let mut buffer = vec![0; 4096];
            let mut listeners = Vec::<ReadChannelSend>::new();

            let (mut read, mut write) = tokio::io::split(tls_stream);

            if handshake_tx.send(()).is_err() {
                anyhow::bail!("connection refused!");
            }
            tracing::info!("connection with node at {addr} has been established!");

            loop {
                tokio::select! {
                    res = read.read(&mut buffer) => match res {
                        Ok(n) => {
                            listeners.retain(|l| !l.is_closed());
                            let bytes = Arc::new(buffer[..n].to_vec());

                            for listener in listeners.iter() {
                                listener.send(Arc::clone(&bytes))?;
                            }
                        },
                        Err(e) => tracing::error!("read node error: {e}"),
                    },
                    Some(msg) = rx.recv() => match msg {
                        NodeInnerMsg::NewListener(listener) => listeners.push(listener),
                        NodeInnerMsg::Write(bytes) => write.write_all(bytes.as_slice()).await?,
                        NodeInnerMsg::Close => break,
                    }
                }
            }

            #[allow(unreachable_code)]
            anyhow::Ok(())
        };

        tokio::spawn(async move {
            if let Err(e) = connection_loop.await {
                tracing::error!("connection loop error: {e}");
            }
        });

        handshake_rx.await?;
        self.connections.write().insert(addr, tx);

        Ok(())
    }

    pub fn write(&self, addr: SocketAddr, bytes: Vec<u8>) -> anyhow::Result<()> {
        self.send_msg(addr, NodeInnerMsg::Write(bytes))
    }

    pub fn close(&self, addr: SocketAddr) -> anyhow::Result<()> {
        {
            self.connections.write().remove(&addr);
        }

        self.send_msg(addr, NodeInnerMsg::Close)
    }

    pub fn reader(&self, addr: SocketAddr) -> anyhow::Result<ReadChannelRecv> {
        let (tx, rx) = sync::mpsc::unbounded_channel();
        self.send_msg(addr, NodeInnerMsg::NewListener(tx))?;
        Ok(rx)
    }

    fn send_msg(&self, addr: SocketAddr, msg: NodeInnerMsg) -> anyhow::Result<()> {
        let sender = {
            let connections = self.connections.read();
            connections
                .get(&addr)
                .with_context(|| "connection should be established")
                .cloned()?
        };

        sender.send(msg)?;
        Ok(())
    }
}

impl Drop for TlsNode {
    fn drop(&mut self) {
        let addrs = {
            let connections = self.connections.read();
            connections
                .keys()
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        };

        for addr in addrs.into_iter() {
            self.close(addr).ok();
        }
    }
}

enum NodeInnerMsg {
    Write(Vec<u8>),
    NewListener(ReadChannelSend),
    Close,
}
