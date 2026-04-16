use std::fs;
use std::path::Path;
use std::sync::Arc;

use rama::tls::rustls::{
    dep::{
        rustls::{
            self,
            RootCertStore, ServerConfig,
            pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
            server::WebPkiClientVerifier,
        },
        tokio_rustls::{self, TlsAcceptor, TlsConnector},
    },
    server::TlsAcceptorDataBuilder,
};

use crate::{
    config::{ClientTlsConfig, ServerTlsConfig},
    error::AppError,
};

#[derive(Clone)]
pub struct ClientTlsContext {
    pub connector: TlsConnector,
    pub server_name: ServerName<'static>,
}

pub type ServerTlsAcceptor = TlsAcceptor;

pub fn build_client_tls_context(config: &ClientTlsConfig) -> Result<Option<ClientTlsContext>, AppError> {
    if !config.enabled {
        return Ok(None);
    }

    let root_store = load_root_store(&config.ca_cert_path)?;

    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);
    let client_config = match client_auth_material(config)? {
        Some((certs, key)) => builder
            .with_client_auth_cert(certs, key)
            .map_err(|err| AppError::Boxed(format!("build client tls config failed: {err}")))?,
        None => builder.with_no_client_auth(),
    };

    let server_name = ServerName::try_from(config.server_name.clone())
        .map_err(|err| AppError::InvalidConfig(format!("invalid tls.server_name: {err}")))?;

    Ok(Some(ClientTlsContext {
        connector: TlsConnector::from(Arc::new(client_config)),
        server_name,
    }))
}

pub fn build_server_tls_acceptor(config: &ServerTlsConfig) -> Result<Option<TlsAcceptor>, AppError> {
    if !config.enabled {
        return Ok(None);
    }

    let certs = load_certificates(&config.cert_path)?;
    let key = load_private_key(&config.key_path)?;
    let server_config = if config.require_client_auth {
        let root_store = load_root_store(&config.client_ca_cert_path)?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|err| AppError::Boxed(format!("build client verifier failed: {err}")))?;
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|err| AppError::Boxed(format!("build server tls config failed: {err}")))?
    } else {
        TlsAcceptorDataBuilder::new(certs, key)
            .map_err(|err| AppError::Boxed(format!("build server tls acceptor data failed: {err}")))?
            .into_rustls_config()
    };

    Ok(Some(tokio_rustls::TlsAcceptor::from(Arc::new(server_config))))
}

fn client_auth_material(
    config: &ClientTlsConfig,
) -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>, AppError> {
    if config.client_cert_path.trim().is_empty() || config.client_key_path.trim().is_empty() {
        return Ok(None);
    }

    Ok(Some((
        load_certificates(&config.client_cert_path)?,
        load_private_key(&config.client_key_path)?,
    )))
}

fn load_root_store(path: &str) -> Result<RootCertStore, AppError> {
    let mut store = RootCertStore::empty();
    for cert in load_certificates(path)? {
        store
            .add(cert)
            .map_err(|err| AppError::Boxed(format!("add certificate to root store failed: {err}")))?;
    }
    Ok(store)
}

fn load_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, AppError> {
    let bytes = fs::read(path)?;
    let mut certs = Vec::new();

    for cert in CertificateDer::pem_slice_iter(&bytes) {
        let cert = cert.map_err(|err| {
            AppError::Boxed(format!(
                "parse certificate pem failed for {}: {err}",
                Path::new(path).display()
            ))
        })?;
        certs.push(cert);
    }

    if certs.is_empty() {
        return Err(AppError::InvalidConfig(format!(
            "no certificates found in {}",
            Path::new(path).display()
        )));
    }

    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, AppError> {
    PrivateKeyDer::from_pem_file(path).map_err(|err| {
        AppError::Boxed(format!(
            "load private key failed for {}: {err}",
            Path::new(path).display()
        ))
    })
}
