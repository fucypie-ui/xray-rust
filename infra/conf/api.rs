use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiConfig {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub listen: String,
}

impl ApiConfig {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            services: Vec::new(),
            listen: String::new(),
        }
    }
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.services.push(service.into());
        self
    }
}

impl ApiConfig {
    pub fn validate(&self) -> crate::common::errors::Result<()> {
        if self.tag.is_empty() { return Err(crate::common::errors::Error::Config("API tag can't be empty.".into())); }
        Ok(())
    }
    pub fn enabled_services(&self) -> Vec<&'static str> {
        self.services.iter().filter_map(|name| match name.to_ascii_lowercase().as_str() {
            "reflectionservice" => Some("ReflectionService"), "handlerservice" => Some("HandlerService"),
            "loggerservice" => Some("LoggerService"), "statsservice" => Some("StatsService"),
            "observatoryservice" => Some("ObservatoryService"), "routingservice" => Some("RoutingService"), _ => None,
        }).collect()
    }
}
