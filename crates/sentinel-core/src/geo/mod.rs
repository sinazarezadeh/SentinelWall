use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};
use anyhow::Result;

#[cfg(feature = "geo")]
use maxminddb::{geoip2, Reader};

pub struct GeoDatabase {
    #[cfg(feature = "geo")]
    country_db: Option<Arc<Reader<Vec<u8>>>>,
    #[cfg(feature = "geo")]
    asn_db: Option<Arc<Reader<Vec<u8>>>>,
}

impl GeoDatabase {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "geo")]
            country_db: None,
            #[cfg(feature = "geo")]
            asn_db: None,
        }
    }

    #[cfg(feature = "geo")]
    pub fn load(&mut self, country_path: &Path, asn_path: Option<&Path>) -> Result<()> {
        info!("Loading GeoIP database from {}", country_path.display());

        match Reader::open_readfile(country_path) {
            Ok(reader) => {
                self.country_db = Some(Arc::new(reader));
                info!("GeoIP country database loaded");
            }
            Err(e) => {
                warn!("Failed to load GeoIP country database: {}", e);
            }
        }

        if let Some(asn_path) = asn_path {
            match Reader::open_readfile(asn_path) {
                Ok(reader) => {
                    self.asn_db = Some(Arc::new(reader));
                    info!("GeoIP ASN database loaded");
                }
                Err(e) => {
                    warn!("Failed to load GeoIP ASN database: {}", e);
                }
            }
        }

        Ok(())
    }

    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        #[cfg(feature = "geo")]
        if let Some(db) = &self.country_db {
            if let Ok(result) = db.lookup::<geoip2::Country>(ip) {
                return result.country
                    .and_then(|c| c.iso_code)
                    .map(|s| s.to_string());
            }
        }
        None
    }

    pub fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        #[cfg(feature = "geo")]
        if let Some(db) = &self.asn_db {
            if let Ok(result) = db.lookup::<geoip2::Asn>(ip) {
                return result.autonomous_system_number;
            }
        }
        None
    }

    pub fn is_available(&self) -> bool {
        #[cfg(feature = "geo")]
        return self.country_db.is_some();
        #[cfg(not(feature = "geo"))]
        false
    }
}

impl Default for GeoDatabase {
    fn default() -> Self {
        Self::new()
    }
}
