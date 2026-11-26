#[cfg(test)]
mod tests {
    use crate::common::net::{Address, Destination, Network};
    use crate::core::format::CONFIG_FORMAT_JSON;
    use crate::core::functions::{create_object, dial, dial_udp, start_instance};
    use crate::infra::conf::Config;
    use crate::testing::servers::tcp::{Server as TcpServer, xor_processor};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_create_object() {
        let cfg = Config::default();
        let inst = create_object(None, &cfg);
        assert!(inst.is_ok());
    }

    #[test]
    fn test_start_instance_valid_json() {
        let json_cfg = r#"{
            "inbounds": [
                {
                    "protocol": "dokodemo-door",
                    "port": 10888,
                    "settings": {
                        "address": "127.0.0.1",
                        "port": 80
                    }
                }
            ],
            "outbounds": [
                {
                    "protocol": "freedom"
                }
            ]
        }"#;

        let instance = start_instance(CONFIG_FORMAT_JSON, json_cfg.as_bytes());
        assert!(instance.is_ok());
    }

    #[test]
    fn test_start_instance_invalid_json() {
        let invalid = b"{ invalid json }";
        let instance = start_instance(CONFIG_FORMAT_JSON, invalid);
        assert!(instance.is_err());
    }

    #[tokio::test]
    async fn test_xray_dial_stream() {
        let server = TcpServer::start(None, Some(xor_processor(b'c')), None)
            .await
            .unwrap();
        let dest = Destination {
            network: Network::Tcp,
            address: Address::ip(server.addr().ip()),
            port: server.addr().port(),
        };

        let json_cfg = r#"{
            "inbounds": [],
            "outbounds": [
                {
                    "protocol": "freedom"
                }
            ]
        }"#;

        let instance = start_instance(CONFIG_FORMAT_JSON, json_cfg.as_bytes()).unwrap();

        let mut conn = dial(&instance, &dest).await.unwrap();

        let payload = b"Hello Xray Core Dial Test!";
        conn.write_all(payload).await.unwrap();

        let mut buf = vec![0u8; payload.len()];
        conn.read_exact(&mut buf).await.unwrap();

        let expected: Vec<u8> = payload.iter().map(|b| b ^ b'c').collect();
        assert_eq!(buf, expected);

        server.close();
    }

    #[tokio::test]
    async fn test_xray_dial_udp() {
        let json_cfg = r#"{
            "inbounds": [],
            "outbounds": [
                {
                    "protocol": "freedom"
                }
            ]
        }"#;

        let instance = start_instance(CONFIG_FORMAT_JSON, json_cfg.as_bytes()).unwrap();
        let conn = dial_udp(&instance).await;
        assert!(conn.is_ok());
        let udp_conn = conn.unwrap();
        assert!(!udp_conn.is_closed());
        udp_conn.close().await;
        assert!(udp_conn.is_closed());
    }

    #[tokio::test]
    async fn test_close_cancels_core_dial_and_releases_both_ends() {
        use std::time::Duration;
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;
        use tokio::time::timeout;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, [b'x']);
            ready_tx.send(()).unwrap();
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0, "Close left the outbound dial connection alive");
        });
        let config: Config = serde_json::from_str(r#"{"outbounds":[{"protocol":"freedom"}]}"#).unwrap();
        let instance = crate::core::Instance::from_config(config).unwrap();
        let dest = Destination::tcp(Address::ip(address.ip()), address.port());
        let mut connection = dial(&instance, &dest).await.unwrap();
        connection.write_all(b"x").await.unwrap();
        timeout(Duration::from_secs(5), ready_rx).await.unwrap().unwrap();
        instance.close().unwrap();
        let mut byte = [0];
        assert_eq!(timeout(Duration::from_secs(5), connection.read(&mut byte)).await.unwrap().unwrap(), 0);
        timeout(Duration::from_secs(5), peer).await.unwrap().unwrap();
        assert!(matches!(dial(&instance, &dest).await, Err(crate::common::errors::Error::Closed)));
    }
}
