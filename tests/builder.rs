#[cfg(test)]
mod tests {
    use firecracker_sdk::FirecrackerBuilder;

    #[test]
    fn test_build_without_api_socket_fails() {
        let builder = FirecrackerBuilder::new("firecracker");
        let result = builder.build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Api socket or configuration file"));
    }

    #[test]
    fn test_firecracker_binary_resolution() {
        // nonexistent absolute path
        let mut builder = FirecrackerBuilder::new("/nonexistent/firecracker");
        builder.with_api_socket_path("/tmp/test.sock".into());
        let result = builder.build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));

        // nonexistent in PATH
        let mut builder = FirecrackerBuilder::new("nonexistent_firecracker_binary");
        builder.with_api_socket_path("/tmp/test.sock".into());
        let result = builder.build();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not found in PATH")
        );

        // absolute path resolves
        let firecracker_path = which::which("firecracker").expect("firecracker in PATH");
        let mut builder = FirecrackerBuilder::new(firecracker_path);
        builder.with_api_socket_path("/tmp/test.sock".into());
        let result = builder.build();
        assert!(result.is_ok());

        // relative name resolves via which
        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_api_socket_path("/tmp/test.sock".into());
        let result = builder.build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_mmds_size_limit() {
        const MAX_SIZE: usize = 512_000_000;

        // too large
        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_api_socket_path("/tmp/test.sock".into());
        builder.with_mmds_size_limit(600_000_000);
        let result = builder.build();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("mmds-size-limit too large")
        );

        // boundary: max is valid
        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_api_socket_path("/tmp/test.sock".into());
        builder.with_mmds_size_limit(MAX_SIZE);
        let result = builder.build();
        assert!(result.is_ok());

        // boundary: max + 1 fails
        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_api_socket_path("/tmp/test.sock".into());
        builder.with_mmds_size_limit(MAX_SIZE + 1);
        let result = builder.build();
        assert!(result.is_err());
    }

    #[test]
    fn test_http_payload_limit() {
        const MIN_SIZE: usize = 1024;
        const MAX_SIZE: usize = 10_000_000;

        // too large
        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_api_socket_path("/tmp/test.sock".into());
        builder.with_http_api_max_payload_limit(20_000_000);
        let result = builder.build();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("http-api-max-payload-limit too large")
        );

        // too small
        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_api_socket_path("/tmp/test.sock".into());
        builder.with_http_api_max_payload_limit(512);
        let result = builder.build();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("http-api-max-payload-limit too small")
        );

        // boundary: min - 1 fails
        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_api_socket_path("/tmp/test.sock".into());
        builder.with_http_api_max_payload_limit(MIN_SIZE - 1);
        let result = builder.build();
        assert!(result.is_err());

        // boundary: min is valid
        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_api_socket_path("/tmp/test.sock".into());
        builder.with_http_api_max_payload_limit(MIN_SIZE);
        let result = builder.build();
        assert!(result.is_ok());

        // boundary: max is valid
        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_api_socket_path("/tmp/test.sock".into());
        builder.with_http_api_max_payload_limit(MAX_SIZE);
        let result = builder.build();
        assert!(result.is_ok());

        // boundary: max + 1 fails
        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_api_socket_path("/tmp/test.sock".into());
        builder.with_http_api_max_payload_limit(MAX_SIZE + 1);
        let result = builder.build();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_file() {
        // valid config file succeeds
        let temp_dir = tempfile::TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.json");
        std::fs::write(&config_path, "{}").unwrap();

        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_config_file(config_path);
        let result = builder.build();
        assert!(result.is_ok());

        // nonexistent config file fails
        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_config_file("/nonexistent/config.json".into());
        let result = builder.build();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Configuration file not found")
        );
    }

    #[test]
    fn test_build_with_nonexistent_seccomp_filter_fails() {
        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_api_socket_path("/tmp/test.sock".into());
        builder.with_seccomp_filter("/nonexistent/seccomp.json".into());
        let result = builder.build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Seccomp filter file not found"));
    }

    #[test]
    fn test_builder_all_options() {
        let mut builder = FirecrackerBuilder::new("firecracker");

        builder
            .with_api_socket_path("/tmp/test.sock".into())
            .with_pci_support(true)
            .with_boot_timer(true)
            .with_id("test-vm".to_string())
            .with_logger_level(firecracker_sdk::models::logger::Level::Info)
            .with_log_file("/tmp/firecracker.log".into())
            .with_metrics_file("/tmp/firecracker.metrics".into())
            .with_mmds_size_limit(1024)
            .with_http_api_max_payload_limit(5000)
            .with_disable_seccomp(true);

        let result = builder.build();
        assert!(result.is_ok());
    }
}
