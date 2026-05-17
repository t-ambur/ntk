extern crate reqwest;
use reqwest::{Client,redirect::Policy, Response};
use reqwest::header::LOCATION;
use serde_json::Value;
use reqwest::header::CONTENT_LENGTH;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use futures_util::StreamExt;

use crate::error::NtkError;
use crate::util;

const MAC_LOOKUP_URL_1: &'static str = "https://api.macvendors.com/";
const MAC_LOOKUP_URL_2: &'static str = "https://api.maclookup.app/v2/macs/";

/// Either dumps the GET response to a file is download_path was specified or to stdout.
async fn print_content(content: &str, download_path: Option<String>) -> Result<(), NtkError> {
    match download_path {
        Some(p) => {
            let mut file = File::create(&p)
                .await
                .or_else(|e| Err(NtkError::FetchFileCreationError(e)))?;
            file.write_all(content.as_bytes())
                .await
                .or_else(|e| Err(NtkError::FetchFileWriteError(e)))?;
            println!("\nOutput response to: {p}");
        },
        None => { println!("{}", content); }
    };
    Ok(())
}

/// Automatically attempts to parse the fetch response based on the content_type header in the response.
/// For example: JSON response is parsed into a string before dumping to stdout or a file
async fn handle_content_type(resp: Response, download_path: Option<String>) -> Result<(), NtkError> {
    match resp.headers().get("Content-Type") {
        Some(v) => {
            let content_type = v.to_str().or_else(|e| Err(NtkError::HttpHeaderToStringFailure(e)))?;
            match content_type {
                "application/json" => {
                    let json: Value = resp.json().await.or_else(|e| Err(NtkError::FetchFailedToGetJson(e)))?;
                    let text = json.to_string();
                    print_content(&text, download_path).await?;
                }
                "text/plain" => {
                    let text = resp.text().await.or_else(|e| Err(NtkError::FetchFailedToGetTextBody(e)))?;
                    print_content(&text, download_path).await?;
                }
                "text/html" => {
                    let text = resp.text().await.or_else(|e| Err(NtkError::FetchFailedToGetTextBody(e)))?;
                    print_content(&text, download_path).await?;
                }
                _ => {
                    if content_type.contains("text") {
                        let text = resp.text().await.or_else(|e| Err(NtkError::FetchFailedToGetTextBody(e)))?;
                        print_content(&text, download_path).await?;
                        return Ok(())
                    }
                    eprintln!("Unexpected content type: {:?}", content_type);
                    if content_type.contains("byte") {
                        eprintln!("For bytes you should use the -d (or: --download, -O) flag instead.")
                    }
                }
            }
        },
        None => {
            println!("{}", resp.text().await.or_else(|e| Err(NtkError::FetchFailedToGetTextBody(e)))?);
        }
    }
    Ok(())
}

/// Runs a HTTP GET request against the specified URL or IP address
pub async fn run_fetch(url_or_ip: &str, ignore_certs: bool, show_headers: bool, no_content: bool, download_path: Option<String>, max_hops: u8, http: bool) -> Result<(), NtkError> {
    let client = Client::builder()
        .redirect(Policy::none()) // Handle redirects manually
        .tls_danger_accept_invalid_certs(ignore_certs)
        .build()
        .or_else(|e| Err(NtkError::ReqwestClientBuildFailure(e)))?;

    let mut url = String::from(url_or_ip);

    if !url.starts_with("http://") && !url.starts_with("https://") {
        url = format!("{}://{}", if http { "http" } else { "https" } , url);
    }

    for hop in 0..max_hops {
        println!("\nRequest #{} to URL: {}", hop + 1, url);

        let resp = client.get(&url).send().await.or_else(|e| Err(NtkError::ReqwestSendFailure(e)))?;
        println!("{} - {:?}", resp.status().as_str(), resp.status().canonical_reason().unwrap_or("Unknown"));

        if show_headers {
            println!("Response Headers:");
            for (k, v) in resp.headers() {
                println!("{}: {:?}", k, v);
            }
            println!();
        }

        // check for redirect
        if let Some(loc) = resp.headers().get(LOCATION) {
            let loc = loc.to_str().or_else(|e| Err(NtkError::HttpHeaderToStringFailure(e)))?;

            let new_url = if loc.starts_with("http") {
                loc.to_string()
            } else {
                let base = reqwest::Url::parse(&url).or_else(|e| Err(NtkError::UrlParseFailure(e)))?;
                base.join(loc).or_else(|e| Err(NtkError::UrlParseFailure(e)))?.to_string()
            };

            println!("Redirect -> {}", new_url);
            url = new_url;
        } else {
            if hop <= 0 {
                println!("(No redirects)")
            } else if !no_content {
                handle_content_type(resp, download_path).await?;
            }
            break;
        }
    }
    
    Ok(())
}

/// Collects a GET to try to discover a MAC Address OUI from two remote databases
pub async fn run_get_mac_vendor(mac: &str, ignore_certs: bool) -> Result<(), NtkError> {
    util::assert_valid_mac_oci(&mac);

    let client = Client::builder()
        .tls_danger_accept_invalid_certs(ignore_certs)
        .build()
        .or_else(|e| Err(NtkError::ReqwestClientBuildFailure(e)))?;

    let url1= format!("{}{}", MAC_LOOKUP_URL_1, mac);

    let resp = client.get(url1).send().await.or_else(|e| Err(NtkError::ReqwestSendFailure(e)))?;
    if resp.status().is_success() {
        println!("{}", resp.text().await.or_else(|e| Err(NtkError::FetchFailedToGetTextBody(e)))?);
        return Ok(())
    }

    let url2 = format!("{}{}", MAC_LOOKUP_URL_2, mac);
    let resp = client.get(url2).send().await.or_else(|e| Err(NtkError::ReqwestSendFailure(e)))?;
    
    if resp.status().is_success() {
        match resp.json::<Value>().await {
            Ok(json) => {
                match json.get("company").and_then(|v| v.as_str()) {
                    Some(company) => {
                        if company.is_empty() {
                            println!("Was unable to find a vendor for '{}'", mac);
                        } else {
                            println!("{}", company)
                        }
                    },
                    None => eprintln!("'company' field not found or not a string in JSON response."),
                }
            }
            Err(e) => eprintln!("Failed to parse JSON: {}", e),
        }
    } else {
        println!("Was unable to find a vendor for '{}'", mac);
    }
    
    Ok(())
}

/// Executes a GET that downloads the remote resource to a file instead of stdout.
/// Shows a neat progress indicator that uses carriage return to update inline
pub async fn run_download(url_or_ip: &str, ignore_certs: bool, show_headers: bool, download_path: Option<String>, http: bool) -> Result<(), NtkError> {
    let client = Client::builder()
        .tls_danger_accept_invalid_certs(ignore_certs)
        .build()
        .or_else(|e| Err(NtkError::ReqwestClientBuildFailure(e)))?;

    let mut url = String::from(url_or_ip);

    if !url.starts_with("http://") && !url.starts_with("https://") {
        url = format!("{}://{}", if http { "http" } else { "https" } , url);
    }

    let resp = client.get(url).send().await.or_else(|e| Err(NtkError::ReqwestSendFailure(e)))?;

    if show_headers {
        println!("Response Headers:");
        for (k, v) in resp.headers() {
            println!("{}: {:?}", k, v);
        }
        println!();
    }

    if !resp.status().is_success() {
        return Err(NtkError::FetchResponseFailure(resp))
    }

    let total_size = resp
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|len| len.to_str().ok())
        .and_then(|len| len.parse::<u64>().ok());

    let fname = match download_path {
        Some(s) => { s },
        None => {
            // Redirects sometimes put the filename in the CONTENT_DISPOSITION header
            // It appears in the form:
            // "attachment; filename=ntk-v0.3.1-linux-musl-x86-native.tar.gz"
            match resp
                .headers()
                .get(reqwest::header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| {
                    v.split(';')
                        .map(str::trim)
                        .find(|part| part.to_lowercase().starts_with("filename="))
                        .map(|part| part.trim_start_matches("filename=").to_string())
                }) {
                    // Return the extracted filename from CONTENT_DISPOSITION header when present
                    Some(cd_name) => cd_name,
                    // Otherwise, attept to grab it from the last 'segment' of the path
                    None => {
                        resp
                            .url()
                            .path_segments()
                            .and_then(|segments| segments.last())
                            .and_then(|name| if name.is_empty() { None } else { Some(name) })
                            .unwrap_or_else(|| resp.url().host_str().unwrap_or("ntk-downloaded-file"))
                            .to_string()
                    }
                }
         }
    };

    println!("Downloading file: '{}'", &fname);

    let mut file = File::create(&fname)
        .await
        .or_else(|e| Err(NtkError::FetchFileCreationError(e)))?;
    let mut stream = resp.bytes_stream();
    let mut downloaded: u64 = 0;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.or_else(|e| Err(NtkError::HttpGetChunkFailure(e)))?;
        file.write_all(&chunk)
            .await
            .or_else(|e| Err(NtkError::FetchFileWriteError(e)))?;

        downloaded += chunk.len() as u64;

        if let Some(total) = total_size {
            let percentage = (downloaded as f64 / total as f64) * 100.0;
            print!("\rDownloading... {:>6.2}%   ", percentage);
        }
    }

    let mb = downloaded as f64 / 1_048_576.0;
    println!("\nFinished downloading file: '{}' ({:.2} MB)", &fname, mb);

    Ok(())
}