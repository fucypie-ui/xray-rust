/// Path construction matches the pinned Go Config's getServiceName / getTun*
/// methods, including empty names and the custom /service/Tun|TunMulti syntax.
pub struct CustomServiceName {
    pub name: String,
}

fn escape_segment(segment: &str) -> String {
    let mut escaped = String::new();
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~$&+:=@".contains(&byte) {
            escaped.push(byte as char);
        } else {
            use std::fmt::Write;
            write!(escaped, "%{byte:02X}").expect("writing a String cannot fail");
        }
    }
    escaped
}

impl CustomServiceName {
    pub fn new(name: impl Into<String>) -> Self { Self { name: name.into() } }

    fn parts(&self) -> (String, String, String) {
        if !self.name.starts_with('/') {
            return (escape_segment(&self.name), "Tun".into(), "TunMulti".into());
        }
        let last = self.name.rfind('/').unwrap();
        let service = self.name[1..last.max(1)].split('/')
            .map(escape_segment).collect::<Vec<_>>().join("/");
        let mut methods = self.name[last + 1..].split('|');
        let tun = escape_segment(methods.next().unwrap_or(""));
        let multi = methods.next().map(escape_segment).unwrap_or_else(|| tun.clone());
        (service, tun, multi)
    }

    pub fn method_path(&self) -> String {
        let (service, tun, _) = self.parts();
        format!("/{service}/{tun}")
    }

    pub fn multi_method_path(&self) -> String {
        let (service, _, multi) = self.parts();
        format!("/{service}/{multi}")
    }
}
