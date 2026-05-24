extern crate reqwest;
use clap::ValueEnum;
use reqwest::ClientBuilder;
use serde_json::Value;
use std::fs;

use crate::error::NtkError;

#[derive(Debug, Clone, ValueEnum)]
pub enum HttpMethod {
    Post,
    Patch,
    Put,
    Delete,
}

fn method_str(method: &HttpMethod) -> &'static str {
    match method {
        HttpMethod::Post   => "POST",
        HttpMethod::Patch  => "PATCH",
        HttpMethod::Put    => "PUT",
        HttpMethod::Delete => "DELETE",
    }
}

/// Runs a HTTP POST / PATCH / PUT / DELETE request against the specified URL or IP address
pub async fn run_out(
    url_or_ip: &str,
    method: HttpMethod,
    body_path: Option<String>,
    ignore_certs: bool,
    http: bool
) -> Result<(), NtkError> {
    let client = ClientBuilder::new()
        .tls_danger_accept_invalid_certs(ignore_certs)
        .build()
        .or_else(|e| Err(NtkError::ReqwestClientBuildFailure(e)))?;

    let url = if url_or_ip.starts_with("http://") || url_or_ip.starts_with("https://") {
        url_or_ip.to_string()
    } else {
        format!("{}://{}", if http { "http" } else { "https" }, url_or_ip)
    };

    let body: Option<Value> = match body_path {
        Some(path) => {
            let contents = fs::read_to_string(path)
                .map_err(NtkError::FetchFileCreationError)?;
            let parsed = serde_json::from_str(&contents)
                .map_err(NtkError::JsonParseFailure)?;
            Some(parsed)
        }
        None => None,
    };

    let builder = match method {
        HttpMethod::Post   => client.post(&url),
        HttpMethod::Patch  => client.patch(&url),
        HttpMethod::Put    => client.put(&url),
        HttpMethod::Delete => client.delete(&url),
    };

    let builder = match &body {
        Some(json) => builder.json(json),
        None => builder,
    };

    let resp = builder
        .send()
        .await
        .or_else(|e| Err(NtkError::ReqwestSendFailure(e)))?;

    let is_json = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"));

    let status = resp.status();

    let body = resp
        .text()
        .await
        .map_err(NtkError::FetchFailedToGetTextBody)?;

    println!("{} {} ->\n {} - {:?}\n",
        method_str(&method),
        url,
        status.as_str(),
        status.canonical_reason().unwrap_or("Unknown")
    );

    if !body.is_empty() {
        if is_json {
            if let Ok(json) = serde_json::from_str::<Value>(&body) {
                println!("{}\n", serde_json::to_string_pretty(&json).unwrap_or(body));
            }
        } else {
            println!("{}\n", body);
        }
    }

    Ok(())
}
