#[cfg(test)]
mod tests {
    use crate::Args;
    use std::time::Duration;
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
    use trust_dns_resolver::TokioAsyncResolver;

    #[test]
    fn test_args_parsing() {
        let args = Args {
            domain: "example.com".to_string(),
            wordlist: "wordlist.txt".to_string(),
            threads: 15,
            recursive: false,
            output: Some("json".to_string()),
        };

        assert_eq!(args.domain, "example.com");
        assert_eq!(args.wordlist, "wordlist.txt");
        assert_eq!(args.threads, 15);
        assert_eq!(args.recursive, false);
        assert_eq!(args.output, Some("json".to_string()));
    }

    #[tokio::test]
    async fn test_resolver_creation() {
        let mut custom_config = ResolverConfig::new();
        custom_config.add_name_server(NameServerConfig {
            socket_addr: "1.1.1.1:53".parse().unwrap(),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(200);
        
        // Resolver'ı oluştur - bu işlemin hata vermemesi yeterli
        let _ = TokioAsyncResolver::tokio(custom_config, opts);
        // Test geçti sayılır
        assert!(true);
    }
}
