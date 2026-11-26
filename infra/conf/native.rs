//! Native Xray protobuf configuration. Wire decoding is provided by prost and
//! prost-reflect against descriptors exported from the pinned Go reference.
//! TypedMessage.value is always protobuf, never JSON hidden in a bytes field.
use std::sync::LazyLock;
use prost_reflect::{DescriptorPool, DynamicMessage, MapKey, ReflectMessage, Value as ProtoValue};
use serde_json::{Value, json};
use crate::common::errors::{Error, Result};
use super::{Config, InboundConfig, OutboundConfig};

static DESCRIPTORS: LazyLock<DescriptorPool> = LazyLock::new(|| {
    DescriptorPool::decode(include_bytes!("native/descriptor.pb").as_slice())
        .expect("pinned Go protobuf descriptor set")
});

pub(crate) fn descriptors() -> &'static DescriptorPool { &DESCRIPTORS }

pub(crate) fn decode_message(name: &str, data: &[u8]) -> Result<DynamicMessage> {
    let descriptor = descriptors().get_message_by_name(name)
        .ok_or_else(|| Error::Config(format!("unknown protobuf message type: {}", name)))?;
    DynamicMessage::decode(descriptor, data)
        .map_err(|error| Error::Config(format!("failed to decode {}: {}", name, error)))
}

/// Use field descriptors for names, enums, byte arrays, maps and nested messages.
/// Only the application/proxy configuration shapes are adapted below.
pub(crate) fn message_json(message: &DynamicMessage) -> Result<Value> {
    let descriptor = message.descriptor();
    if descriptor.full_name() == "xray.common.serial.TypedMessage" {
        let name = message.get_field_by_name("type").and_then(|value| value.as_str().map(str::to_owned)).unwrap_or_default();
        let data = message.get_field_by_name("value").and_then(|value| value.as_bytes().cloned()).unwrap_or_default();
        return Ok(json!({"@type":name, "value":message_json(&decode_message(&name, &data)?)?}));
    }
    if descriptor.full_name() == "xray.common.net.IPOrDomain" {
        if let Some(value) = message.get_field_by_name("domain")
            && let Some(domain) = value.as_str() && !domain.is_empty() { return Ok(json!(domain)); }
        if let Some(value) = message.get_field_by_name("ip") && let Some(ip) = value.as_bytes() {
            let address = match ip.len() {
                4 => std::net::IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
                16 => std::net::IpAddr::V6(std::net::Ipv6Addr::from(<[u8;16]>::try_from(ip.as_ref()).expect("checked IPv6 length"))),
                _ => return Err(Error::Config("invalid protobuf IP address length".into())),
            };
            return Ok(json!(address.to_string()));
        }
    }
    let mut output = serde_json::Map::new();
    for field in descriptor.fields() {
        if field.supports_presence() && !message.has_field(&field) { continue; }
        output.insert(field.json_name().into(), proto_json(message.get_field(&field).as_ref(), &field.kind())?);
    }
    Ok(Value::Object(output))
}

fn proto_json(value: &ProtoValue, kind: &prost_reflect::Kind) -> Result<Value> {
    Ok(match value {
        ProtoValue::Bool(value) => json!(value),
        ProtoValue::I32(value) => json!(value),
        ProtoValue::I64(value) => json!(value),
        ProtoValue::U32(value) => json!(value),
        ProtoValue::U64(value) => json!(value),
        ProtoValue::F32(value) => json!(value),
        ProtoValue::F64(value) => json!(value),
        ProtoValue::String(value) => json!(value),
        ProtoValue::Bytes(value) => json!(value.to_vec()),
        ProtoValue::EnumNumber(number) => match kind {
            prost_reflect::Kind::Enum(descriptor) => descriptor.get_value(*number).map_or_else(|| json!(number), |value| json!(value.name())),
            _ => json!(number),
        },
        ProtoValue::Message(message) => message_json(message)?,
        ProtoValue::List(values) => Value::Array(values.iter().map(|value| proto_json(value, kind)).collect::<Result<_>>()?),
        ProtoValue::Map(values) => {
            let value_kind = match kind {
                prost_reflect::Kind::Message(descriptor) => descriptor.map_entry_value_field().kind(),
                _ => return Err(Error::Config("invalid protobuf map descriptor".into())),
            };
            let mut output = serde_json::Map::new();
            for (key, value) in values {
                let key = match key {
                    MapKey::Bool(value) => value.to_string(),
                    MapKey::I32(value) => value.to_string(),
                    MapKey::I64(value) => value.to_string(),
                    MapKey::U32(value) => value.to_string(),
                    MapKey::U64(value) => value.to_string(),
                    MapKey::String(value) => value.clone(),
                };
                output.insert(key, proto_json(value, &value_kind)?);
            }
            Value::Object(output)
        }
    })
}

pub(crate) fn decode_config(data: &[u8]) -> Result<Config> {
    let root = decode_message("xray.core.Config", data)?;
    let root = message_json(&root)?;
    let mut config = Config::default();
    for app in array(&root, "app") { apply_app(&mut config, app)?; }
    // Extensions are deliberately ignored, as specified by core/config.proto.
    for inbound in array(&root, "inbound") {
        let receiver = typed(&inbound["receiverSettings"], "xray.app.proxyman.ReceiverConfig")?;
        let (protocol, settings) = proxy_settings(&inbound["proxySettings"], true)?;
        let stream_settings = stream_config(receiver.get("streamSettings"))?;
        let mut ports = Vec::new();
        for range in array(&receiver["portList"], "range") {
            let first = range["from"].as_u64().unwrap_or(0);
            let last = range["to"].as_u64().unwrap_or(first);
            if last > u16::MAX as u64 || first > last { return Err(Error::Config("invalid protobuf inbound port range".into())); }
            ports.extend((first..=last).map(|port| port as u16));
        }
        if ports.is_empty() && protocol == "tun" { ports.push(0); }
        if ports.is_empty() { return Err(Error::Config("Listen on AnyIP but no Port(s) set in InboundDetour.".into())); }
        let sniffing = receiver.get("sniffingSettings").map(|sniff| json!({
            "enabled":sniff["enabled"], "destOverride":sniff["destinationOverride"],
            "metadataOnly":sniff["metadataOnly"], "routeOnly":sniff["routeOnly"],
        }));
        for port in ports {
            config.inbounds.push(InboundConfig {
                tag: inbound["tag"].as_str().map(str::to_owned),
                port: Some(port), listen: receiver["listen"].as_str().map(str::to_owned),
                protocol: protocol.clone(), settings: Some(settings.clone()),
                stream_settings: stream_settings.clone(), sniffing: sniffing.clone(),
            });
        }
    }
    for outbound in array(&root, "outbound") {
        let sender = if outbound.get("senderSettings").is_some() {
            typed(&outbound["senderSettings"], "xray.app.proxyman.SenderConfig")?
        } else { json!({}) };
        let (protocol, settings) = proxy_settings(&outbound["proxySettings"], false)?;
        config.outbounds.push(OutboundConfig {
            tag: outbound["tag"].as_str().map(str::to_owned), protocol,
            settings: Some(settings), stream_settings: stream_config(sender.get("streamSettings"))?, mux: None,
        });
    }
    Ok(config)
}

fn typed(value: &Value, expected: &str) -> Result<Value> {
    if value["@type"].as_str() != Some(expected) {
        return Err(Error::Config(format!("expected protobuf {}, found {}", expected, value["@type"])));
    }
    Ok(value["value"].clone())
}

fn array<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    value.get(field).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn from_value<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    serde_json::from_value(value).map_err(|error| Error::Config(format!("invalid native protobuf config: {}", error)))
}

fn apply_app(config: &mut Config, app: &Value) -> Result<()> {
    let name = app["@type"].as_str().unwrap_or("");
    let value = &app["value"];
    match name {
        "xray.app.dispatcher.Config" | "xray.app.proxyman.InboundConfig" | "xray.app.proxyman.OutboundConfig" => {}
        "xray.app.stats.Config" => config.stats = Some(json!({})),
        "xray.app.policy.Config" => {
            let mut native = crate::app::policy::config_pb::Config::default();
            if let Some(levels) = value["level"].as_object() {
                for (level, policy) in levels {
                    let level = level.parse::<u32>().map_err(|error| Error::Config(error.to_string()))?;
                    let second = |name| policy["timeout"].get(name).map(|value| crate::app::policy::config_pb::Second::new(value["value"].as_u64().unwrap_or(0) as u32));
                    native.level.insert(level, crate::app::policy::config_pb::Policy {
                        timeout: policy.get("timeout").map(|_| crate::app::policy::config_pb::PolicyTimeout {
                            handshake: second("handshake"), connection_idle: second("connectionIdle"),
                            uplink_only: second("uplinkOnly"), downlink_only: second("downlinkOnly"),
                        }),
                        stats: policy.get("stats").map(|stats| crate::app::policy::config_pb::PolicyStats {
                            user_uplink: stats["userUplink"].as_bool().unwrap_or(false),
                            user_downlink: stats["userDownlink"].as_bool().unwrap_or(false),
                            user_online: stats["userOnline"].as_bool().unwrap_or(false),
                        }),
                        buffer: policy.get("buffer").map(|buffer| crate::app::policy::config_pb::PolicyBuffer {
                            connection: buffer["connection"].as_i64().unwrap_or(0) as i32,
                        }),
                    });
                }
            }
            native.system = value.get("system").map(|system| crate::app::policy::config_pb::SystemPolicy {
                stats: system.get("stats").map(|stats| crate::app::policy::config_pb::SystemPolicyStats {
                    inbound_uplink: stats["inboundUplink"].as_bool().unwrap_or(false),
                    inbound_downlink: stats["inboundDownlink"].as_bool().unwrap_or(false),
                    outbound_uplink: stats["outboundUplink"].as_bool().unwrap_or(false),
                    outbound_downlink: stats["outboundDownlink"].as_bool().unwrap_or(false),
                }),
            });
            config.policy = Some(super::policy::PolicyConfig { native:Some(native), ..Default::default() });
        }
        "xray.app.commander.Config" => {
            let services = array(value, "service").iter().filter_map(|service| match service["@type"].as_str()? {
                "xray.app.commander.ReflectionConfig" => Some("ReflectionService"),
                "xray.app.proxyman.command.Config" => Some("HandlerService"),
                "xray.app.stats.command.Config" => Some("StatsService"),
                "xray.app.log.command.Config" => Some("LoggerService"),
                "xray.app.router.command.Config" => Some("RoutingService"),
                "xray.core.app.observatory.command.Config" => Some("ObservatoryService"),
                _ => None,
            }).collect::<Vec<_>>();
            config.api = Some(from_value(json!({"tag":value["tag"], "listen":value["listen"], "services":services}))?);
        }
        "xray.app.metrics.Config" => config.metrics = Some(from_value(value.clone())?),
        "xray.core.app.observatory.Config" => config.observatory = Some(from_value(json!({
            "subjectSelector":value["subjectSelector"], "probeURL":value["probeUrl"],
            "probeInterval":format!("{}ns", value["probeInterval"].as_i64().unwrap_or(0)),
            "enableConcurrency":value["enableConcurrency"],
        }))?),
        "xray.core.app.observatory.burst.Config" => {
            let ping = &value["pingConfig"];
            config.burst_observatory = Some(from_value(json!({
                "subjectSelector":value["subjectSelector"],
                "pingConfig":{
                    "destination":ping["destination"], "connectivity":ping["connectivity"],
                    "interval":format!("{}ns", ping["interval"].as_i64().unwrap_or(0)),
                    "timeout":format!("{}ns", ping["timeout"].as_i64().unwrap_or(0)),
                    "sampling":ping["samplingCount"], "httpMethod":ping["httpMethod"],
                },
            }))?);
        }
        "xray.app.version.Config" => config.version = Some(from_value(json!({"min":value["minVersion"], "max":value["maxVersion"]}))?),
        "xray.app.log.Config" => {
            let level = match value["errorLogLevel"].as_str().unwrap_or("Warning") {
                "Debug" => "debug", "Info" => "info", "Error" => "error", _ => "warning",
            };
            config.log = Some(from_value(json!({"loglevel":level, "access":value["accessLogPath"], "error":value["errorLogPath"]}))?);
        }
        "xray.app.dns.fakedns.FakeDnsPoolMulti" => {
            config.fake_dns = Some(Value::Array(array(value, "pools").iter().map(|pool| json!({"ipPool":pool["ipPool"],"poolSize":pool["size"]})).collect()));
        }
        "xray.app.geodata.Config" => config.geodata = Some(value.clone()),
        "xray.app.dns.Config" => config.dns = Some(dns_config(value)?),
        "xray.app.router.Config" => config.routing = Some(router_config(value)?),
        _ => return Err(Error::Config(format!("unregistered native protobuf app: {}", name))),
    }
    Ok(())
}

fn user(value: &Value) -> Result<Value> {
    let account = &value["account"];
    let mut output = account["value"].as_object().cloned().unwrap_or_default();
    if let Some(security) = output.remove("securitySettings") {
        output.insert("security".into(), json!(match security["type"].as_str().unwrap_or("AUTO") {
            "AES128_GCM" => "aes-128-gcm", "CHACHA20_POLY1305" => "chacha20-poly1305", _ => "auto",
        }));
    }
    if let Some(tests) = output.remove("testsEnabled") { output.insert("experiments".into(), tests); }
    if let Some(username) = output.remove("username") { output.insert("user".into(), username); }
    if let Some(password) = output.get("password").cloned() { output.insert("pass".into(), password); }
    if let Some(key) = output.remove("key") { output.insert("password".into(), key); }
    if let Some(cipher) = output.remove("cipherType") {
        output.insert("method".into(), json!(match cipher.as_str().unwrap_or("") {
            "AES_128_GCM" => "aes-128-gcm", "AES_256_GCM" => "aes-256-gcm",
            "CHACHA20_POLY1305" => "chacha20-poly1305", "XCHACHA20_POLY1305" => "xchacha20-poly1305", _ => "unknown",
        }));
    }
    output.insert("level".into(), value["level"].clone());
    output.insert("email".into(), value["email"].clone());
    Ok(Value::Object(output))
}

fn endpoint(value: &Value) -> Result<Value> {
    Ok(json!({"address":value["address"],"port":value["port"],
        "users":array(value,"user").iter().map(user).collect::<Result<Vec<_>>>()?}))
}

fn proxy_settings(typed: &Value, inbound: bool) -> Result<(String, Value)> {
    let name = typed["@type"].as_str().unwrap_or("");
    let value = &typed["value"];
    let (protocol, settings) = match name {
        "xray.proxy.socks.ServerConfig" => ("socks", json!({
            "auth":if value["authType"] == "PASSWORD" { "password" } else { "noauth" },
            "accounts":value["accounts"],"udp":value["udpEnabled"], "ip":value["address"],"userLevel":value["userLevel"],
        })),
        "xray.proxy.http.ServerConfig" => ("http", json!({"accounts":value["accounts"], "allowTransparent":value["allowTransparent"], "userLevel":value["userLevel"]})),
        "xray.proxy.socks.ClientConfig" => ("socks", json!({"servers":[endpoint(&value["server"])?]})),
        "xray.proxy.http.ClientConfig" => ("http", json!({"servers":[endpoint(&value["server"])?],"headers":value["header"]})),
        "xray.proxy.vless.outbound.Config" => ("vless", json!({"vnext":[endpoint(&value["vnext"])?]})),
        "xray.proxy.vmess.outbound.Config" => ("vmess", json!({"vnext":[endpoint(&value["Receiver"])?]})),
        "xray.proxy.trojan.ClientConfig" | "xray.proxy.shadowsocks.ClientConfig" | "xray.proxy.hysteria.ClientConfig" => {
            let protocol = if name.contains("trojan") { "trojan" } else if name.contains("hysteria") { "hysteria" } else { "shadowsocks" };
            let mut server = endpoint(&value["server"])?;
            if let Some(account) = server["users"].as_array().and_then(|users| users.first()).cloned() {
                if let Some(object) = account.as_object() { for (key,value) in object { server[key] = value.clone(); } }
            }
            (protocol, json!({"servers":[server]}))
        }
        "xray.proxy.vless.inbound.Config" | "xray.proxy.vmess.inbound.Config" | "xray.proxy.trojan.ServerConfig" | "xray.proxy.hysteria.ServerConfig" => {
            let protocol = if name.contains("vless") { "vless" } else if name.contains("vmess") { "vmess" } else if name.contains("trojan") { "trojan" } else { "hysteria" };
            let users = if protocol == "vmess" { array(value,"user") } else { array(value,"users") };
            let mut settings = json!({"clients":users.iter().map(user).collect::<Result<Vec<_>>>()?});
            if value.get("fallbacks").is_some() { settings["fallbacks"] = value["fallbacks"].clone(); }
            if protocol == "vless" { settings["decryption"] = value["decryption"].clone(); }
            (protocol, settings)
        }
        "xray.proxy.shadowsocks_2022.ServerConfig" | "xray.proxy.shadowsocks_2022.MultiUserServerConfig" | "xray.proxy.shadowsocks_2022.ClientConfig" => {
            let mut settings = value.clone();
            settings["password"] = value["key"].clone();
            if value.get("users").is_some() { settings["clients"] = Value::Array(array(value,"users").iter().map(user).collect::<Result<_>>()?); }
            ("shadowsocks",settings)
        }
        "xray.proxy.shadowsocks.ServerConfig" => {
            let clients = array(value,"users").iter().map(user).collect::<Result<Vec<_>>>()?;
            let first = clients.first().cloned().unwrap_or(json!({}));
            ("shadowsocks",json!({"clients":clients,"method":first["method"],"password":first["password"]}))
        }
        "xray.proxy.freedom.Config" => {
            let strategy = match value["domainStrategy"].as_str().unwrap_or("AS_IS") {
                "USE_IP" => "UseIP", "USE_IP4" => "UseIPv4", "USE_IP6" => "UseIPv6", "FORCE_IP" => "ForceIP", _ => "AsIs",
            };
            let mut settings = json!({"domainStrategy":strategy,"userLevel":value["userLevel"]});
            if let Some(server) = value["destinationOverride"].get("server") {
                settings["redirect"] = json!(format!("{}:{}", server["address"].as_str().unwrap_or(""), server["port"]));
            }
            ("freedom",settings)
        }
        "xray.proxy.blackhole.Config" => ("blackhole", json!({"response":{"type":if value["response"]["@type"].as_str().is_some_and(|name| name.contains("HTTP")) {"http"} else {"none"}}})),
        "xray.proxy.dokodemo.Config" => ("dokodemo-door",json!({"address":value["rewriteAddress"],"port":value["rewritePort"],"followRedirect":value["followRedirect"],"userLevel":value["userLevel"],"network":if array(value,"allowedNetworks").contains(&json!("UDP")) {"udp"} else {"tcp"}})),
        "xray.proxy.loopback.Config" => ("loopback",json!({"inboundTag":value["inboundTag"]})),
        "xray.proxy.wireguard.DeviceConfig" => ("wireguard",json!({"secretKey":value["secretKey"],"address":value["endpoint"],"peers":value["peers"],"mtu":value["mtu"],"reserved":value["reserved"]})),
        "xray.proxy.dns.Config" => ("dns",value.clone()),
        "xray.proxy.tun.Config" => ("tun",value.clone()),
        _ => return Err(Error::Config(format!("unregistered native protobuf {} proxy: {}", if inbound {"inbound"} else {"outbound"}, name))),
    };
    Ok((protocol.into(),settings))
}

fn stream_config(value: Option<&Value>) -> Result<Option<super::StreamSettingsConfig>> {
    let Some(value) = value else { return Ok(None); };
    let network = value["protocolName"].as_str().filter(|name| !name.is_empty()).unwrap_or("tcp");
    let mut output = json!({"network":network});
    for security in array(value,"securitySettings") {
        let name = security["@type"].as_str().unwrap_or("");
        if name.contains(".tls.") { output["security"] = json!("tls"); output["tlsSettings"] = security["value"].clone(); }
        else if name.contains(".reality.") { output["security"] = json!("reality"); output["realitySettings"] = security["value"].clone(); }
        else { return Err(Error::Config(format!("unregistered protobuf security: {}",name))); }
    }
    for transport in array(value,"transportSettings") {
        let protocol = transport["protocolName"].as_str().unwrap_or("");
        let key = match protocol {"tcp"=>"tcpSettings","websocket"|"ws"=>"wsSettings","httpupgrade"=>"httpupgradeSettings","grpc"=>"grpcSettings","splithttp"|"xhttp"=>"xhttpSettings","mkcp"|"kcp"=>"kcpSettings", other=>return Err(Error::Config(format!("unregistered protobuf transport: {}",other)))};
        output[key] = transport["settings"]["value"].clone();
    }
    Ok(Some(from_value(output)?))
}

fn dns_config(value: &Value) -> Result<Value> {
    let servers = array(value,"nameServer").iter().map(|server| {
        let endpoint = &server["address"];
        let host = endpoint["address"].as_str().unwrap_or("");
        let port = endpoint["port"].as_u64().unwrap_or(53);
        json!({"address":host,"port":port,"skipFallback":server["skipFallback"],"tag":server["tag"]})
    }).collect::<Vec<_>>();
    Ok(json!({"servers":servers,"disableCache":value["disableCache"],"disableFallback":value["disableFallback"],"disableFallbackIfMatch":value["disableFallbackIfMatch"],"tag":value["tag"]}))
}

fn router_config(value: &Value) -> Result<super::RoutingConfig> {
    let mut rules = Vec::new();
    for rule in array(value,"rule") {
        let mut output = json!({"type":"field","outboundTag":rule["tag"],"inboundTag":rule["inboundTag"],"user":rule["userEmail"],"protocol":rule["protocol"]});
        let domains = array(rule,"domain").iter().filter_map(|domain| {
            let text = domain["value"].as_str()?;
            Some(json!(format!("{}{}",match domain["type"].as_str().unwrap_or("") {"Full"=>"full:","RootDomain"=>"domain:","Regex"=>"regexp:",_=>"keyword:"},text)))
        }).collect::<Vec<_>>();
        if !domains.is_empty() { output["domain"] = json!(domains); }
        rules.push(output);
    }
    from_value(json!({"rules":rules}))
}
