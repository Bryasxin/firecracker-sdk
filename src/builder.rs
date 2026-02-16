//! Firecracker instance builder, which returns an unstarted Firecracker wrapper
use crate::dto::LoggerLevel;
use crate::firecracker::Firecracker;
use std::path::PathBuf;

/// Used for quickly generating builder pattern setter methods
macro_rules! with {
    // Match [`Option<T>`]
    ($field_name:expr, Option<$inner_type:ty>) => {
        paste::paste! {
            pub fn [<with_ $field_name>](&mut self, $field_name: $inner_type) -> &mut Self {
                self.[<$field_name>] = Some($field_name);
                self
            }
        }
    };
    ($method_name:expr, $field_name:expr, Option<$inner_type:ty>) => {
        paste::paste! {
            pub fn [<with_ $method_name>](&mut self, $field_name: $inner_type) -> &mut Self {
                self.[<$field_name>] = Some($field_name);
                self
            }
        }
    };

    // Match normal types
    ($field_name:expr, $field_type:ty) => {
        paste::paste! {
            pub fn [<with_ $field_name>](&mut self, $field_name: $field_type) -> &mut Self {
                self.[<$field_name>] = $field_name;
                self
            }
        }
    };
    ($method_name:expr, $field_name:expr, $field_type:ty) => {
        paste::paste! {
            pub fn [<with_ $method_name>](&mut self, $field_name: $field_type) -> &mut Self {
                self.[<$field_name>] = $field_name;
                self
            }
        }
    };
}

#[derive(Debug, Default, Clone)]
pub struct FirecrackerBuilder {
    firecracker_binary: PathBuf,

    /// Path to unix domain socket used by the API
    api_socket_path: Option<PathBuf>,
    /// Enable PCI support
    enable_pci: bool,
    /// Path to a file that contains the microVM configuration in JSON format
    config_file: Option<PathBuf>,
    /// Loads boot timer device for logging elapsed time since `InstanceStart` command
    enable_boot_timer: bool,
    /// Print the data format version of the provided snapshot state file
    describe_snapshot_file: Option<PathBuf>,
    /// Instance ID
    id: Option<String>,
    /// Logger level
    logger_level: Option<LoggerLevel>,
    /// Path to a FIFO or a file used for configuring the logger on startup
    log_file: Option<PathBuf>,
    /// Path to a file that contains metadata in JSON format to add to the MMDS
    metadata_file: Option<PathBuf>,
    /// Path to a FIFO or a file used for configuring the metrics on startup
    metrics_file: Option<PathBuf>,
    /// MMDS data store limit, in bytes
    mmds_size_limit: Option<usize>,
    /// HTTP API request payload max size, in bytes
    http_api_max_payload_limit: Option<usize>,
    /// Logger module filter
    logger_module_filter: Option<String>,
    /// Disables seccomp
    disable_seccomp: Option<bool>,
    /// Parent process CPU time (wall clock, microseconds)
    parent_cpu_time: Option<usize>,
    /// Specifies the path to a custom seccomp filter
    seccomp_filter: Option<String>,
    /// Process start CPU time (wall clock, microseconds)
    start_time_cpu: Option<usize>,
    /// Process start time (wall clock, microseconds)
    start_time: Option<usize>,
    /// Outputs the level in the logs
    show_level: Option<bool>,
    /// Includes the file path and line number of the log's origin
    show_log_origin: Option<bool>,
}

impl FirecrackerBuilder {
    /// Create a new Firecracker builder
    pub fn new(firecracker_binary: impl Into<PathBuf>) -> Self {
        Self {
            firecracker_binary: firecracker_binary.into(),
            ..Default::default()
        }
    }

    /// Build unstarted Firecracker
    pub fn build(self) -> Result<Firecracker, crate::Error> {
        let firecracker_binary = &self.firecracker_binary;

        if !firecracker_binary.exists() {
            return Err(crate::Error::InvalidConfiguration(format!(
                "Firecracker binary not found: {}",
                firecracker_binary.display()
            )));
        }

        if !firecracker_binary.is_file() {
            return Err(crate::Error::InvalidConfiguration(format!(
                "Firecracker path is not a file: {}",
                firecracker_binary.display()
            )));
        }

        if self.api_socket_path.is_none() && self.config_file.is_none() {
            return Err(crate::Error::InvalidConfiguration(
                "Api socket or configuration file must be specified".to_string(),
            ));
        }

        if let Some(ref path) = self.config_file
            && !path.exists()
        {
            return Err(crate::Error::InvalidConfiguration(format!(
                "Configuration file not found: {}",
                path.display()
            )));
        }

        if let Some(ref path) = self.seccomp_filter {
            let path_buf = std::path::Path::new(path);
            if !path_buf.exists() {
                return Err(crate::Error::InvalidConfiguration(format!(
                    "Seccomp filter file not found: {}",
                    path
                )));
            }
        }

        if let Some(size) = self.mmds_size_limit {
            const MMDS_SIZE_LIMIT_MAX: usize = 512_000_000;
            if size > MMDS_SIZE_LIMIT_MAX {
                return Err(crate::Error::InvalidConfiguration(format!(
                    "mmds-size-limit too large: {} (max: {})",
                    size, MMDS_SIZE_LIMIT_MAX
                )));
            }
        }

        if let Some(size) = self.http_api_max_payload_limit {
            const HTTP_API_MAX_PAYLOAD_LIMIT_MAX: usize = 10_000_000;
            const HTTP_API_MAX_PAYLOAD_LIMIT_MIN: usize = 1024;
            if size > HTTP_API_MAX_PAYLOAD_LIMIT_MAX {
                return Err(crate::Error::InvalidConfiguration(format!(
                    "http-api-max-payload-limit too large: {} (max: {})",
                    size, HTTP_API_MAX_PAYLOAD_LIMIT_MAX
                )));
            }
            if size < HTTP_API_MAX_PAYLOAD_LIMIT_MIN {
                return Err(crate::Error::InvalidConfiguration(format!(
                    "http-api-max-payload-limit too small: {} (min: {})",
                    size, HTTP_API_MAX_PAYLOAD_LIMIT_MIN
                )));
            }
        }

        let mut firecracker = Firecracker::new(self.firecracker_binary);

        if let Some(path) = self.api_socket_path {
            firecracker.add_arg("--api-sock");
            firecracker.add_arg(path.to_string_lossy().to_string());
        }

        if self.enable_pci {
            firecracker.add_arg("--enable-pci");
        }

        if let Some(path) = self.config_file {
            firecracker.add_arg("--config-file");
            firecracker.add_arg(path.to_string_lossy().to_string());
        }

        if self.enable_boot_timer {
            firecracker.add_arg("--boot-timer");
        }

        if let Some(path) = self.describe_snapshot_file {
            firecracker.add_arg("--describe-snapshot");
            firecracker.add_arg(path.to_string_lossy().to_string());
        }

        if let Some(id) = self.id {
            firecracker.add_arg("--id");
            firecracker.add_arg(id);
        }

        if let Some(level) = self.logger_level {
            firecracker.add_arg("--level");
            firecracker.add_arg(level.to_string());
        }

        if let Some(path) = self.log_file {
            firecracker.add_arg("--log-path");
            firecracker.add_arg(path.to_string_lossy().to_string());
        }

        if let Some(path) = self.metadata_file {
            firecracker.add_arg("--metadata");
            firecracker.add_arg(path.to_string_lossy().to_string());
        }

        if let Some(path) = self.metrics_file {
            firecracker.add_arg("--metrics-path");
            firecracker.add_arg(path.to_string_lossy().to_string());
        }

        if let Some(size) = self.mmds_size_limit {
            firecracker.add_arg("--mmds-size-limit");
            firecracker.add_arg(size.to_string());
        }

        if let Some(size) = self.http_api_max_payload_limit {
            firecracker.add_arg("--http-api-max-payload-size");
            firecracker.add_arg(size.to_string());
        }

        if let Some(filter) = self.logger_module_filter {
            firecracker.add_arg("--module");
            firecracker.add_arg(filter);
        }

        if self.disable_seccomp == Some(true) {
            firecracker.add_arg("--no-seccomp");
        }

        if let Some(time) = self.parent_cpu_time {
            firecracker.add_arg("--parent-cpu-time-us");
            firecracker.add_arg(time.to_string());
        }

        if let Some(filter) = self.seccomp_filter {
            firecracker.add_arg("--seccomp-filter");
            firecracker.add_arg(filter);
        }

        if let Some(time) = self.start_time_cpu {
            firecracker.add_arg("--start-time-cpu-us");
            firecracker.add_arg(time.to_string());
        }

        if let Some(time) = self.start_time {
            firecracker.add_arg("--start-time-us");
            firecracker.add_arg(time.to_string());
        }

        if self.show_level == Some(true) {
            firecracker.add_arg("--show-level");
        }

        if self.show_log_origin == Some(true) {
            firecracker.add_arg("--show-log-origin");
        }

        Ok(firecracker)
    }
}

impl FirecrackerBuilder {
    with!(firecracker_binary, PathBuf);
    with!(pci_support, enable_pci, bool);
    with!(api_socket_path, Option<PathBuf>);
    with!(config_file, Option<PathBuf>);
    with!(boot_timer, enable_boot_timer, bool);
    with!(describe_snapshot_file, Option<PathBuf>);
    with!(id, Option<String>);
    with!(logger_level, Option<LoggerLevel>);
    with!(log_file, Option<PathBuf>);
    with!(metadata_file, Option<PathBuf>);
    with!(metrics_file, Option<PathBuf>);
    with!(mmds_size_limit, Option<usize>);
    with!(http_api_max_payload_limit, Option<usize>);
    with!(logger_module_filter, Option<String>);
    with!(disable_seccomp, Option<bool>);
    with!(parent_cpu_time, Option<usize>);
    with!(seccomp_filter, Option<String>);
    with!(start_time_cpu, Option<usize>);
    with!(start_time, Option<usize>);
    with!(show_level, Option<bool>);
    with!(show_log_origin, Option<bool>);
}
