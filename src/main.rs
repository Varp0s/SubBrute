/*
 * SubBrute - Fast Subdomain Scanner
 * 
 * A high-performance subdomain scanner built in Rust
 * GitHub: https://github.com/Varp0s/subbrute
 * Author: Varp0s
 */

#[cfg(test)]
mod tests;

use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::future::join_all;
use tokio::sync::Semaphore;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use serde_json::json;
use chrono::Local;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};

const VERSION: &str = "1.0.0";
const BANNER: &str = r#"
 ____        _     ____             _       
/ ___| _   _| |__ |  _ \ _ __ _   _| |_ ___ 
\___ \| | | | '_ \| |_) | '__| | | | __/ _ \
 ___) | |_| | |_) |  _ <| |  | |_| | ||  __/
|____/ \__,_|_.__/|_| \_\_|   \__,_|\__\___|
                                           
"#;

const TIMEOUT_MS: u64 = 200; 
const INITIAL_BATCH_SIZE: usize = 300;
const MAX_RETRIES: usize = 3; 
const PARALLEL_RESOLVERS: bool = true; 
const PREFETCH_DNS: bool = true;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'd', long = "domain")]
    domain: String,

    #[arg(short = 'w', long = "wordlist")]
    wordlist: String,   
    
    #[arg(short = 't', long = "threads", default_value_t = 15)]
    threads: usize,

    #[arg(short = 'o', long = "output")]
    output: Option<String>,
}

#[tokio::main]
async fn main() {    
    println!("{}", BANNER.bright_cyan());
    println!("{}", format!("SubBrute v{} - Fast Subdomain Scanner", VERSION).bright_green());
    println!("{}", "Developer: Varp0s".bright_blue());
    println!("{}", "=".repeat(60).bright_yellow());

    let args = Args::parse();

    let domain = Arc::new(args.domain);
    let wordlist_path = args.wordlist;
    let concurrency = args.threads;
    let output_format = args.output.clone();
    println!("{}", "Loading Wordlist...".bright_blue());
    let wordlist = tokio::fs::read_to_string(&wordlist_path).await
        .expect(&format!("{}", "Wordlist could not be read".bright_red()));

    let subdomain_list: Vec<String> = wordlist
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .collect();
        
    let total_words = subdomain_list.len();
        
    let processed_words = Arc::new(AtomicUsize::new(0));
    let found_domains = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let progress_bar = ProgressBar::new(total_words as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({percent}%)")
            .unwrap()
            .progress_chars("##-")
    );
    
    let start_time = Local::now();
    println!("\n{} {}", "🕒 Scan start time:".bright_blue(), 
             start_time.format("%d-%m-%Y %H:%M:%S").to_string().bright_yellow());
    println!("{} {} {}", "🔍 Scan starts:".bright_blue(), 
             domain.bright_green(), 
             format!("(Keywords: {})", total_words).bright_yellow());
    println!("{}", "=".repeat(60).bright_yellow());
    let mut resolvers = Vec::new();
    fn create_resolver(config: ResolverConfig, name: &str) -> TokioAsyncResolver {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(TIMEOUT_MS);
        opts.attempts = 1;
        opts.cache_size = 1024; 
        opts.use_hosts_file = false;
        opts.preserve_intermediates = false;
        opts.try_tcp_on_error = false;
        opts.num_concurrent_reqs = 100;
        opts.validate = false;

        println!("{} {}", "🌐 Adding DNS Resolver:".bright_blue(), name.bright_green());
        TokioAsyncResolver::tokio(config, opts)
    }
    
    resolvers.push(Arc::new(create_resolver(ResolverConfig::cloudflare(), "Cloudflare (1.1.1.1)")));
    resolvers.push(Arc::new(create_resolver(ResolverConfig::google(), "Google (8.8.8.8)")));
    resolvers.push(Arc::new(create_resolver(ResolverConfig::quad9(), "Quad9 (9.9.9.9)")));
    let mut custom_config = ResolverConfig::new();
    custom_config.add_name_server(NameServerConfig {
        socket_addr: "1.0.0.1:53".parse().unwrap(),  
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    });
    resolvers.push(Arc::new(create_resolver(custom_config, "Cloudflare Alternatif (1.0.0.1)")));
    
    let mut opendns_config = ResolverConfig::new();
    opendns_config.add_name_server(NameServerConfig {
        socket_addr: "208.67.222.222:53".parse().unwrap(),  
        protocol: Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    });
    resolvers.push(Arc::new(create_resolver(opendns_config, "OpenDNS (208.67.222.222)")));

    println!("{} {}", "✅ Total number of DNS Resolvers:".bright_blue(),
             format!("{} quantity", resolvers.len()).bright_green());
    println!("{}", "=".repeat(60).bright_yellow());// Wildcard kontrolü
    println!("{}", "Wildcard check in progress...".bright_blue());
    let wildcard_ips = check_wildcard(&resolvers[0], &domain).await;
    if let Some(ref ips) = wildcard_ips {
        println!("{} {}", "⚠️ Wildcard DNS detected:".bright_yellow(),
                 ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ").bright_red());
    } else {
        println!("{}", "✅ Wildcard DNS not detected".bright_green());
    }
    println!("{}", "=".repeat(60).bright_yellow());
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();

    async fn lookup_domain(
        resolvers: &[Arc<TokioAsyncResolver>],
        full_domain: String,
        wildcard_ips: &Option<Vec<std::net::IpAddr>>,
        max_retry: usize,
        use_parallel: bool
    ) -> Option<(String, Vec<String>, bool, Option<String>)> {
            if use_parallel && resolvers.len() > 1 {            
            let futures = resolvers.iter().map(|resolver| {
                let resolver = resolver.clone();
                let domain = full_domain.clone();
                
                Box::pin(async move {
                    match tokio::time::timeout(
                        Duration::from_millis(TIMEOUT_MS), 
                        resolver.lookup_ip(&domain)
                    ).await {
                        Ok(Ok(lookup_ip)) => {
                            let ips: Vec<_> = lookup_ip.iter().collect();
                            if !ips.is_empty() {
                                return Some(ips);
                            }
                        },
                        _ => {}
                    }
                    None
                })
            }).collect::<Vec<_>>();
            
            let (first_result, _, _) = futures::future::select_all(futures).await;
            
            if let Some(ips) = first_result {
                if let Some(ref wildcard) = wildcard_ips {
                    if ips.iter().any(|ip| wildcard.contains(ip)) {
                        return None; // Wildcard eşleşmesi varsa atla
                    }
                }
                
                let ip_strings = ips.iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>();
                    
                return Some((
                    full_domain,
                    ip_strings,
                    false,
                    None,
                ));
            }
            
            None
        } else {
            for retry in 0..=max_retry {
                let resolver_idx = retry % resolvers.len();
                let resolver = &resolvers[resolver_idx];
                
                let lookup_result = tokio::time::timeout(
                    Duration::from_millis(TIMEOUT_MS), 
                    resolver.lookup_ip(&full_domain)
                ).await;
                
                match lookup_result {
                    Ok(Ok(lookup_ip)) => {
                        let ips: Vec<_> = lookup_ip.iter().collect();
                        if !ips.is_empty() {
                            if let Some(ref wildcard) = wildcard_ips {
                                if ips.iter().any(|ip| wildcard.contains(ip)) {
                                    return None;
                                }
                            }
                            
                            let ip_strings = ips.iter()
                                .map(|ip| ip.to_string())
                                .collect::<Vec<_>>();
                                
                            return Some((
                                full_domain,
                                ip_strings,
                                false,
                                None,
                            ));
                        }
                    },
                    _ => {}
                }
                
                if retry < max_retry {
                    tokio::time::sleep(Duration::from_millis(30 * (retry + 1) as u64)).await;
                }
            }
              None
        }
    }
    let batch_size = INITIAL_BATCH_SIZE;
    let batch_update_interval = 5000;
    let speed_check_time = Arc::new(tokio::sync::Mutex::new(Local::now())); 
    let last_processed = Arc::new(AtomicUsize::new(0));
    
    if PREFETCH_DNS {
        println!("{}", "Preparing DNS cache for fast startup...".bright_blue());
        let prefetch_domains: Vec<String> = subdomain_list.iter()
            .take(10) 
            .map(|sub| format!("{}.{}", sub, domain.as_str()))
            .collect();
            
        let mut prefetch_futures = Vec::new();
        for resolver in &resolvers {
            let resolver = resolver.clone();
            let domains = prefetch_domains.clone();
            
            prefetch_futures.push(tokio::spawn(async move {
                for domain in domains {
                    let _ = resolver.lookup_ip(&domain).await;
                }
            }));
        }
        join_all(prefetch_futures).await;
        println!("{}", "DNS cache prepared".bright_green());
    }

    let mut i = 0;
    while i < subdomain_list.len() {
        let end_idx = (i + batch_size).min(subdomain_list.len());
        let batch = &subdomain_list[i..end_idx];
        
        for sub in batch {
            let sub = sub.clone();
            let domain = Arc::clone(&domain);
            let wildcard_ips = wildcard_ips.clone();
            let resolvers_clone = resolvers.clone();
            let processed_counter = Arc::clone(&processed_words);
            let found_list = Arc::clone(&found_domains);
            let pb = progress_bar.clone();
            let speed_time = Arc::clone(&speed_check_time);
            let last_count = Arc::clone(&last_processed);
            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();

            handles.push(tokio::spawn(async move {
                let full_domain = format!("{}.{}", sub, domain.as_str());
                let domain_info = lookup_domain(
                    &resolvers_clone, 
                    full_domain.clone(), 
                    &wildcard_ips,
                    MAX_RETRIES,
                    PARALLEL_RESOLVERS
                ).await;
                
                if let Some(info) = domain_info {
                    let ip_list = info.1.join(", ");
                    let output = format!("🔥 {} | {}", 
                                        info.0.bright_green(), 
                                        format!("IP: {}", ip_list).bright_blue());
                    println!("{}", output);
                    
                    let mut domains = found_list.lock().await;
                    domains.push(info);
                }
                processed_counter.fetch_add(1, Ordering::Relaxed);
                pb.inc(1);

                let processed = processed_counter.load(Ordering::Relaxed);
                if processed % 1000 == 0 {
                    let mut time = speed_time.lock().await;
                    let now = Local::now();
                    *time = now;
                    last_count.store(processed, Ordering::Relaxed);
                }
                
                drop(permit);
            }));
        }
        i = end_idx;
        if processed_words.load(Ordering::Relaxed) % batch_update_interval == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    join_all(handles).await;

    progress_bar.finish_with_message("Scan completed!");

    let end_time = Local::now();
    let duration = end_time.signed_duration_since(start_time);
    let minutes = duration.num_minutes();
    let seconds = duration.num_seconds() % 60;
    
    let found_count = found_domains.lock().await.len();
    
    println!("\n{}", "=".repeat(60).bright_yellow());
    println!("{}", "🎯 SCAN RESULTS".bright_cyan().bold());
    println!("{}", "-".repeat(60).bright_yellow());
    println!("{} {}", "🌐 Scanned Domain:".bright_blue(), domain.as_str().bright_green());
    println!("{} {}", "📚 Wordlist:".bright_blue(), wordlist_path.bright_green());
    println!("{} {}", "🔢 Total Scanned:".bright_blue(), format!("{} words", total_words).bright_green());
    println!("{} {}", "⏱️ Start Time:".bright_blue(), start_time.format("%H:%M:%S").to_string().bright_green());
    println!("{} {}", "🏁 End Time:".bright_blue(), end_time.format("%H:%M:%S").to_string().bright_green());
    println!("{} {}", "⌛ Total Duration:".bright_blue(),
             format!("{} minutes {} seconds", minutes, seconds).bright_green());
    println!("{} {}", "🔍 Found Domains:".bright_blue(),
             format!("{}", found_count).bright_green().bold());
    println!("{}", "=".repeat(60).bright_yellow());
    
    if found_count > 0 {
        println!("\n{}", "FOUND DOMAINS:".bright_cyan().bold());
        println!("{}", "-".repeat(60).bright_yellow());
        
        let found_list = found_domains.lock().await;
        for (i, (domain, ips, _, _)) in found_list.iter().enumerate() {
            let ip_list = ips.join(", ");
            println!("{} {} - {}", 
                     format!("{}.", i+1).bright_blue(), 
                     domain.bright_green(), 
                     format!("IP: {}", ip_list).bright_yellow());
        }
        println!("{}", "=".repeat(60).bright_yellow());
    }
    
    if let Some(output_format) = output_format {
        let found = found_domains.lock().await;
        match output_format.to_lowercase().as_str() {
            "json" => {
                let json_output = json!(found.iter().map(|(domain, ips, alive, deep)| {
                    json!({
                        "domain": domain,
                        "ips": ips,
                        "alive": alive,
                        "deep_subdomain": deep
                    })
                }).collect::<Vec<_>>());
                
                let output_file = format!("{}_results.json", domain.as_str());
                let mut file = File::create(&output_file).await.expect("Failed to create output file");
                file.write_all(json_output.to_string().as_bytes()).await.expect("Failed to write JSON");
                println!("{} {}", "💾 Results saved to file:".bright_blue(), output_file.bright_green());
            },
            "txt" => {
                let output_file = format!("{}_results.txt", domain.as_str());
                let mut file = File::create(&output_file).await.expect("Failed to create output file");
                
                for (domain, ips, alive, deep) in found.iter() {
                    let line = format!(
                        "Domain: {}\nIPs: {}\nAlive: {}\nDeep Subdomain: {}\n\n",
                        domain,
                        ips.join(", "),
                        alive,
                        deep.as_ref().unwrap_or(&"Not Found".to_string())
                    );
                    file.write_all(line.as_bytes()).await.expect("Failed to write TXT");
                }

                println!("{} {}", "💾 Results saved to file:".bright_blue(), output_file.bright_green());
            },
            _ => {
                println!("{} {}", "⚠️ Unsupported output format:".bright_red(),
                         format!("{}. Only 'json' or 'txt' can be used.", output_format).bright_yellow());
            }
        }
    }

    println!("\n{} {}", "👋 Scan completed!".bright_green().bold(),
             "We wish you good work.".bright_blue());
}

async fn check_wildcard(
    resolver: &Arc<TokioAsyncResolver>,
    domain: &str,
) -> Option<Vec<std::net::IpAddr>> {
    let mut all_ips = Vec::new();
    let mut futures = Vec::new();
    
    for _ in 0..5 {  
        let random_uuid = Uuid::new_v4().to_string();
        let wildcard = format!("{}.{}", random_uuid, domain);
        let resolver_clone = resolver.clone();
        
        futures.push(tokio::spawn(async move {
            match tokio::time::timeout(
                Duration::from_millis(TIMEOUT_MS),
                resolver_clone.lookup_ip(&wildcard)
            ).await {
                Ok(Ok(lookup_ip)) => {
                    let ips: Vec<_> = lookup_ip.iter().collect();
                    if !ips.is_empty() {
                        return Some(ips);
                    }
                }
                _ => {}
            }
            None
        }));
    }
    
    for result in join_all(futures).await {
        if let Ok(Some(ips)) = result {
            for ip in ips {
                if !all_ips.contains(&ip) {
                    all_ips.push(ip);
                }
            }
        }
    }
    
    if !all_ips.is_empty() {
        Some(all_ips)
    } else {
        None
    }
}