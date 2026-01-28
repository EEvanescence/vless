use anyhow::{anyhow, Context, Result};
use clap::Parser;
use colored::*;
use futures::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use chrono::Utc;
use chrono_tz::Asia::Tehran;

// --- Constants ---
const DEFAULT_PROXY_FILE: &str = "edge/assets/p-list-january.txt";
const DEFAULT_OUTPUT_FILE: &str = "sub/ProxyIP-Daily.md";
const DEFAULT_JSON_FILE: &str = "sub/active_proxies.json";
const DEFAULT_HISTORY_FILE: &str = "sub/history.json";
const DEFAULT_MAX_CONCURRENT: usize = 50;
const DEFAULT_TIMEOUT_SECONDS: u64 = 6;
const REQUEST_DELAY_MS: u64 = 50;
const MAX_RETRIES: u32 = 2; // تعداد تلاش مجدد
const RETRY_DELAY_MS: u64 = 1000; // فاصله بین تلاش‌ها
const CHECK_URL: &str = "https://ipp.nscl.ir";

const GOOD_ISPS: &[&str] = &[
    "M247", "OVH", "Vultr", "GCore", "IONOS", "Google", "Amazon", "NetLab", "Akamai", "Turunc",
    "Contabo", "UpCloud", "Tencent", "Hetzner", "Multacom", "HostPapa", "Ultahost", "DataCamp",
    "Bluehost", "Scaleway", "DO Space", "Leaseweb", "Hostinger", "netcup GmbH", "Protilab",
    "ByteDance", "RackSpace", "SiteGround", "Online Ltd", "The Empire", "Cloudflare", "Relink LTD",
    "PQ Hosting", "Gigahost AS", "White Label", "G-Core Labs", "3HCLOUD LLC", "HOSTKEY B.V",
    "DigitalOcean", "3NT SOLUTION", "Zenlayer Inc", "RackNerd LLC", "Plant Holding", "WorkTitans",
    "IROKO Networks", "WorldStream", "Cluster", "The Constant Company", "Cogent Communications",
    "Metropolis networks inc", "Total Uptime Technologies",
];

// --- Structs & Enums ---

#[derive(Parser, Clone)]
#[command(name = "Proxy Checker Pro")]
struct Args {
    #[arg(short, long, default_value = DEFAULT_PROXY_FILE)]
    proxy_file: String,

    #[arg(short, long, default_value = DEFAULT_OUTPUT_FILE)]
    output_file: String,

    #[arg(long, default_value = DEFAULT_JSON_FILE)]
    json_file: String,

    #[arg(long, default_value = DEFAULT_HISTORY_FILE)]
    history_file: String,

    #[arg(long, default_value_t = DEFAULT_MAX_CONCURRENT)]
    max_concurrent: usize,

    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS)]
    timeout: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkerResponse {
    ip: String,
    cf: WorkerCf,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkerCf {
    #[serde(rename = "asOrganization")]
    isp: Option<String>,
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ProxyInfo {
    ip: String,
    port: u16,
    isp: String,
    country_code: String,
    city: String,
    region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HistoryEntry {
    date: String,
    count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ProxyErrorKind {
    Timeout,
    Connect,
    Tls,
    Http,
    Json,
    IpMatch,
    Unknown,
}

// --- Main Function ---

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Create directories if needed
    if let Some(parent) = Path::new(&args.output_file).parent() {
        fs::create_dir_all(parent).context("Failed to create output directory")?;
    }

    // Read proxies
    let proxies = read_proxy_file(&args.proxy_file).context("Failed to read proxy file")?;
    println!("Loaded {} proxies from file", proxies.len());

    // Filter proxies
    let proxies: Vec<String> = proxies
        .into_iter()
        .filter(|line| {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() < 4 { return false; }
            let port_ok = parts[1].trim() == "443";
            let isp_name = parts[3].to_string();
            let isp_ok = GOOD_ISPS.iter().any(|kw| isp_name.contains(kw));
            port_ok && isp_ok
        })
        .collect();
    println!("Filtered to {} candidates (port 443 + ISP whitelist)", proxies.len());

    let self_ip = fetch_self_ip().await.unwrap_or_else(|_| "0.0.0.0".to_string());
    println!("Your real IP: {}", self_ip);

    let active_proxies = Arc::new(Mutex::new(BTreeMap::<String, Vec<(ProxyInfo, u128)>>::new()));
    let error_stats = Arc::new(Mutex::new(HashMap::<ProxyErrorKind, usize>::new()));

    // Run Tasks with Retry Logic
    let tasks = futures::stream::iter(proxies.into_iter().map(|proxy_line| {
        let active_proxies = Arc::clone(&active_proxies);
        let error_stats = Arc::clone(&error_stats);
        let self_ip = self_ip.clone();
        async move {
            tokio::time::sleep(Duration::from_millis(REQUEST_DELAY_MS)).await;
            process_proxy_with_retry(proxy_line, &active_proxies, &error_stats, &self_ip).await;
        }
    }))
    .buffer_unordered(args.max_concurrent)
    .collect::<Vec<()>>();

    tasks.await;

    // Retrieve results
    let locked_proxies = active_proxies.lock().unwrap_or_else(|e| e.into_inner());
    let total_active: usize = locked_proxies.values().map(|v| v.len()).sum();

    // 1. Update History & Generate Graph Link
    let sparkline_url = update_history_and_get_chart(&args.history_file, total_active)?;

    // 2. Write Markdown
    write_markdown_file(&locked_proxies, &args.output_file, &sparkline_url)
        .context("Failed to write Markdown file")?;

    // 3. Write JSON
    write_json_file(&locked_proxies, &args.json_file)
        .context("Failed to write JSON file")?;

    // Terminal Summary
    println!("\n{}", "=== DEAD PROXY SUMMARY ===".bold().white());
    let stats = error_stats.lock().unwrap();
    let mut sorted_stats: Vec<_> = stats.iter().collect();
    sorted_stats.sort_by(|a, b| b.1.cmp(a.1));
    for (kind, count) in sorted_stats {
        println!("{:?}: {}", kind, count.to_string().yellow());
    }
    println!("==========================");
    println!("Total Active: {}", total_active.to_string().green().bold());
    println!("JSON saved to: {}", args.json_file);
    println!("History saved to: {}", args.history_file);

    Ok(())
}

// --- Logic Functions ---

fn classify_error(e: &anyhow::Error) -> ProxyErrorKind {
    let msg = e.to_string().to_lowercase();
    if msg.contains("timeout") || msg.contains("timed out") {
        ProxyErrorKind::Timeout
    } else if msg.contains("tls") || msg.contains("ssl") || msg.contains("certificate") {
        ProxyErrorKind::Tls
    } else if msg.contains("json") || msg.contains("deserialize") {
        ProxyErrorKind::Json
    } else if msg.contains("ip match") {
        ProxyErrorKind::IpMatch
    } else if msg.contains("connection refused")
        || msg.contains("reset by peer")
        || msg.contains("unreachable")
    {
        ProxyErrorKind::Connect
    } else if msg.contains("http") || msg.contains("status") {
        ProxyErrorKind::Http
    } else {
        ProxyErrorKind::Unknown
    }
}

async fn process_proxy_with_retry(
    proxy_line: String,
    active_proxies: &Arc<Mutex<BTreeMap<String, Vec<(ProxyInfo, u128)>>>>,
    error_stats: &Arc<Mutex<HashMap<ProxyErrorKind, usize>>>,
    self_ip: &str,
) {
    let mut last_error = anyhow!("Unknown error");
    
    // Try up to MAX_RETRIES + 1 times
    for attempt in 0..=MAX_RETRIES {
        match process_proxy_inner(&proxy_line, active_proxies, self_ip).await {
            Ok(_) => return, // Success!
            Err(e) => {
                last_error = e;
                if attempt < MAX_RETRIES {
                    let kind = classify_error(&last_error);
                    match kind {
                        ProxyErrorKind::Timeout | ProxyErrorKind::Connect | ProxyErrorKind::Tls => {
                            tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                            continue;
                        },
                        _ => break,
                    }
                }
            }
        }
    }

    // All attempts failed
    let kind = classify_error(&last_error);
    {
        let mut stats = error_stats.lock().unwrap();
        *stats.entry(kind).or_default() += 1;
    }
    
    let ip = proxy_line.split(',').next().unwrap_or("Unknown");
    println!(
        "{}",
        format!("PROXY DEAD ❌ [{:?}]: {} ({})", kind, ip, last_error).red()
    );
}

// این تابع جا افتاده بود، اینجا اضافه شد
async fn process_proxy_inner(
    proxy_line: &str,
    active_proxies: &Arc<Mutex<BTreeMap<String, Vec<(ProxyInfo, u128)>>>>,
    self_ip: &str,
) -> Result<()> {
    let parts: Vec<&str> = proxy_line.split(',').collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid line format"));
    }

    let ip = parts[0];
    let port = parts[1].parse::<u16>().unwrap_or(443);
    let csv_isp = if parts.len() > 3 { parts[3].trim().to_string() } else { "Unknown".to_string() };

    // Pass self_ip to checker
    let (data, ping) = check_proxy_worker(ip, port, self_ip).await?;

    let info = ProxyInfo {
        ip: ip.to_string(), // استفاده از آی‌پی فایل برای جلوگیری از Unknown
        port,
        isp: data.cf.isp.unwrap_or(csv_isp),
        country_code: data.cf.country.unwrap_or_else(|| "XX".to_string()),
        city: data.cf.city.unwrap_or_else(|| "Unknown".to_string()),
        region: data.cf.region.unwrap_or_else(|| "Unknown".to_string()),
    };

    println!(
        "{}",
        format!("PROXY LIVE 🟩: {} ({} ms) - {}", info.ip, ping, info.city).green()
    );

    let mut active_proxies_locked = active_proxies.lock().unwrap_or_else(|e| e.into_inner());
    active_proxies_locked
        .entry(info.country_code.clone())
        .or_default()
        .push((info, ping));

    Ok(())
}

async fn fetch_self_ip() -> Result<String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    match client.get(CHECK_URL).send().await {
        Ok(resp) => {
            if let Ok(json) = resp.json::<WorkerResponse>().await {
                return Ok(json.ip);
            }
        }
        Err(_) => {}
    }
    let resp = client.get("https://api.ipify.org").send().await?.text().await?;
    Ok(resp.trim().to_string())
}

async fn check_proxy_worker(ip: &str, port: u16, _self_ip: &str) -> Result<(WorkerResponse, u128)> {
    use native_tls::TlsConnector;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_native_tls::TlsConnector as TokioTlsConnector;

    let timeout = Duration::from_secs(DEFAULT_TIMEOUT_SECONDS);
    let start_ping = Instant::now();

    // 1. TCP Connect
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(format!("{}:{}", ip, port)))
        .await
        .context("Timeout")?
        .context("Connect Failed")?;

    // 2. TLS Handshake
    let tls = TokioTlsConnector::from(TlsConnector::builder().build()?);
    let mut stream = tokio::time::timeout(timeout, tls.connect("speed.cloudflare.com", tcp))
        .await
        .context("TLS Timeout")?
        .context("TLS Failed")?;

    let ping = start_ping.elapsed().as_millis();

    // 3. Send HTTP Request
    let req = concat!(
        "GET /meta HTTP/1.1\r\n",
        "Host: speed.cloudflare.com\r\n",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n",
        "Accept: */*\r\n",
        "Connection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;

    // 4. Read Response
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        let read_result = tokio::time::timeout(timeout, stream.read(&mut tmp)).await;
        match read_result {
            Ok(Ok(n)) if n == 0 => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            Ok(Err(e)) => return Err(anyhow!("Read Error: {}", e)),
            Err(_) => return Err(anyhow!("Read Timeout")),
        }
    }

    // 5. Parse Body
    let text = String::from_utf8_lossy(&buf);
    let body = if let Some(pos) = text.find("\r\n\r\n") { &text[pos + 4..] } else { &text };
    let body = body.trim();
    if body.is_empty() { return Err(anyhow!("Empty Body")); }

    let v: serde_json::Value = serde_json::from_str(body).context("JSON Error")?;
    let out_ip = v.get("clientIp").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();

    Ok((
        WorkerResponse {
            ip: out_ip,
            cf: WorkerCf {
                isp: v.get("asOrganization").and_then(|v| v.as_str()).map(String::from),
                city: v.get("city").and_then(|v| v.as_str()).map(String::from),
                region: v.get("region").and_then(|v| v.as_str()).map(String::from),
                country: v.get("country").and_then(|v| v.as_str()).map(String::from),
            },
        },
        ping,
    ))
}

fn write_json_file(
    proxies_by_country: &BTreeMap<String, Vec<(ProxyInfo, u128)>>,
    path: &str,
) -> Result<()> {
    let mut all_proxies = Vec::new();
    for list in proxies_by_country.values() {
        for (info, _) in list {
            all_proxies.push(info.clone());
        }
    }
    let file = File::create(path)?;
    serde_json::to_writer_pretty(file, &all_proxies)?;
    Ok(())
}

fn update_history_and_get_chart(history_path: &str, current_count: usize) -> Result<String> {
    let mut history: Vec<HistoryEntry> = if Path::new(history_path).exists() {
        let file = File::open(history_path)?;
        serde_json::from_reader(file).unwrap_or_default()
    } else {
        Vec::new()
    };

    let today = Utc::now().format("%Y-%m-%d").to_string();
    
    if let Some(last) = history.last_mut() {
        if last.date == today {
            last.count = current_count;
        } else {
            history.push(HistoryEntry { date: today, count: current_count });
        }
    } else {
        history.push(HistoryEntry { date: today, count: current_count });
    }

    if history.len() > 30 {
        history.remove(0);
    }

    let file = File::create(history_path)?;
    serde_json::to_writer_pretty(file, &history)?;

    let data_points: Vec<String> = history.iter().map(|h| h.count.to_string()).collect();
    let data_str = data_points.join(",");
    let chart_url = format!(
        "https://quickchart.io/chart?c={{type:'sparkline',data:{{datasets:[{{data:[{}]}}]}}}}&w=120&h=30",
        data_str
    );
    
    Ok(chart_url)
}

fn write_markdown_file(
    proxies_by_country: &BTreeMap<String, Vec<(ProxyInfo, u128)>>,
    output_file: &str,
    sparkline_url: &str,
) -> io::Result<()> {
    let mut file = File::create(output_file)?;
    let total_active = proxies_by_country.values().map(|v| v.len()).sum::<usize>();
    let total_countries = proxies_by_country.len();
    let avg_ping = if total_active > 0 {
        let sum_ping: u128 = proxies_by_country.values().flatten().map(|(_, p)| *p).sum();
        sum_ping / total_active as u128
    } else { 0 };

    let now = Utc::now();
    let tehran_now = now.with_timezone(&Tehran);
    let last_updated_str = tehran_now.format("%a, %d %b %Y %H:%M").to_string();

    writeln!(
        file,
        r##"<p align="left">
 <img src="https://latex.codecogs.com/svg.image?\huge&space;{{\color{{Golden}}\mathrm{{PR{{\color{{black}}\O}}XY\;IP}}" width=220px" />
</p>

> [!NOTE]
> **Active Proxies Trend (30 Days):**
>
> <img src="{sparkline}" alt="Trend" />

> [!WARNING]
> **Daily Fresh Proxies**
>
> Auto-Updated: {last} (UTC+3:30)

<p>
  <img src="https://img.shields.io/badge/Active-{active}-success" />
  <img src="https://img.shields.io/badge/Countries-{countries}-blue" />
  <img src="https://img.shields.io/badge/Avg_Latency-{latency}ms-orange" />
</p>
"##,
        sparkline = sparkline_url,
        last = last_updated_str,
        active = total_active,
        countries = total_countries,
        latency = avg_ping,
    )?;

    // Providers Section
    let top_providers = ["Google", "Amazon", "Cloudflare", "Tencent", "Hetzner"];
    let mut provider_buckets: HashMap<&str, Vec<(ProxyInfo, u128)>> = HashMap::new();
    for prov in top_providers.iter() { provider_buckets.insert(prov, Vec::new()); }

    for list in proxies_by_country.values() {
        for (info, ping) in list {
            for prov in top_providers.iter() {
                if info.isp.to_lowercase().contains(&prov.to_lowercase()) {
                    if let Some(vec) = provider_buckets.get_mut(prov) {
                        vec.push((info.clone(), *ping));
                    }
                }
            }
        }
    }

    for prov in top_providers.iter() {
        if let Some(list) = provider_buckets.get(prov) {
            if !list.is_empty() {
                writeln!(file, "## {} ({})", prov, list.len())?;
                writeln!(file, "<details><summary>Expand</summary>\n")?;
                writeln!(file, "| IP | ISP | Location | Ping |")?;
                writeln!(file, "|:---|:---|:---:|:---:|")?;
                let mut sorted = list.clone();
                sorted.sort_by_key(|&(_, p)| p);
                for (info, ping) in sorted {
                    let emoji = if ping < 1000 { "⚡" } else { "🐢" };
                    writeln!(file, "| `{}` | {} | {} | {}ms {} |", info.ip, info.isp, info.country_code, ping, emoji)?;
                }
                writeln!(file, "\n</details>\n")?;
            }
        }
    }

    // Countries Section
    for (code, list) in proxies_by_country {
        let mut sorted = list.clone();
        sorted.sort_by_key(|&(_, p)| p);
        let flag = country_flag(code);
        writeln!(file, "## {} {} ({})", flag, get_country_name(code), sorted.len())?;
        writeln!(file, "<details><summary>Expand</summary>\n")?;
        writeln!(file, "| IP | ISP | Location | Ping |")?;
        writeln!(file, "|:---|:---|:---:|:---:|")?;
        for (info, ping) in sorted {
            let emoji = if ping < 1000 { "⚡" } else { "🐢" };
            writeln!(file, "| `{}` | {} | {}, {} | {}ms {} |", info.ip, info.isp, info.region, info.city, ping, emoji)?;
        }
        writeln!(file, "\n</details>\n")?;
    }

    Ok(())
}

fn country_flag(code: &str) -> String {
    code.chars().filter_map(|c| {
        if c.is_ascii_alphabetic() {
            Some(char::from_u32(0x1F1E6 + (c.to_ascii_uppercase() as u32 - 'A' as u32)).unwrap())
        } else { None }
    }).collect()
}

fn get_country_name(code: &str) -> String {
    match code.to_uppercase().as_str() {
        "IR" => "Iran".to_string(),
        "US" => "United States".to_string(),
        "DE" => "Germany".to_string(),
        "GB" => "United Kingdom".to_string(),
        "FR" => "France".to_string(),
        "NL" => "Netherlands".to_string(),
        "CA" => "Canada".to_string(),
        "AU" => "Australia".to_string(),
        "JP" => "Japan".to_string(),
        "CN" => "China".to_string(),
        "RU" => "Russia".to_string(),
        "TR" => "Turkey".to_string(),
        "AE" => "United Arab Emirates".to_string(),
        "SG" => "Singapore".to_string(),
        _ => code.to_string(),
    }
}

fn read_proxy_file(file_path: &str) -> io::Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().filter_map(Result::ok).filter(|l| !l.trim().is_empty()).collect())
}

fn provider_logo_html(_: &str) -> Option<String> { None }
