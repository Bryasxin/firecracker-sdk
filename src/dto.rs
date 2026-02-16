//! Firecracker DTOs
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;
use std::fmt::Display;

/// Balloon device descriptor
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balloon {
    /// Target balloon size in MiB
    pub amount_mib: isize,
    /// Whether the balloon should deflate when the guest has memory pressure
    pub deflate_on_oom: bool,
    /// Interval in seconds between refreshing statistics. A non-zero value will enable the statistics. Defaults to 0
    pub stats_polling_interval_s: Option<isize>,
    /// Whether the free page hinting feature is enabled
    pub free_page_hinting: Option<bool>,
    /// Whether the free page reporting feature is enabled
    pub free_page_reporting: Option<bool>,
}

/// Balloon device descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalloonUpdate {
    /// Target balloon size in MiB
    pub amount_mib: isize,
}

/// Describes the balloon device statistics
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalloonStats {
    /// Target number of pages the device aims to hold
    pub target_pages: i64,
    /// Actual number of pages the device is holding
    pub actual_pages: i64,
    /// Target amount of memory (in MiB) the device aims to hold
    pub target_mib: i64,
    /// Actual amount of memory (in MiB) the device is holding
    pub actual_mib: i64,
    /// The amount of memory that has been swapped in (in bytes)
    pub swap_in: Option<i64>,
    /// The amount of memory that has been swapped out to disk (in bytes)
    pub swap_out: Option<i64>,
    /// The number of major page faults that have occurred
    pub major_faults: Option<i64>,
    /// The number of minor page faults that have occurred
    pub minor_faults: Option<i64>,
    /// The amount of memory not being used for any purpose (in bytes)
    pub free_memory: Option<i64>,
    /// The total amount of memory available (in bytes)
    pub total_memory: Option<i64>,
    /// An estimate of how much memory is available (in bytes) for starting new applications, without pushing the system to swap
    pub available_memory: Option<i64>,
    /// The amount of memory, in bytes, that can be quickly reclaimed without additional I/O. Typically these pages are used for caching files from disk
    pub disk_caches: Option<i64>,
    /// The number of successful hugetlb page allocations in the guest
    pub hugetlb_allocations: Option<i64>,
    /// The number of failed hugetlb page allocations in the guest
    pub hugetlb_failures: Option<i64>,
    /// OOM killer invocations, indicating critical memory pressure
    pub oom_kill: Option<i64>,
    /// Counter of Allocation enter a slow path to gain more memory page. The reclaim/scan metrics can reveal what is actually happening
    pub alloc_stall: Option<i64>,
    /// Amount of memory scanned asynchronously
    pub async_scan: Option<i64>,
    /// Amount of memory scanned directly
    pub direct_scan: Option<i64>,
    /// Amount of memory reclaimed asynchronously
    pub async_reclaim: Option<i64>,
    /// Amount of memory reclaimed directly
    pub direct_reclaim: Option<i64>,
}

/// Command used to start a free page hinting run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalloonStartCmd {
    /// If Firecracker should automatically acknowledge when the guest submits a done cmd
    pub acknowledge_on_stop: bool,
}

/// Describes the free page hinting status
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalloonHintingStatus {
    /// The last command issued by the host
    pub host_cmd: isize,
    /// The last command provided by the guest
    pub guest_cmd: Option<isize>,
}

/// Update the statistics polling interval, with the first statistics update scheduled immediately. Statistics cannot be turned on/off after boot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalloonStatsUpdate {
    /// Interval in seconds between refreshing statistics
    pub stats_polling_interval_s: isize,
}

/// The CPU Template defines a set of flags to be disabled from the microvm so that
/// the features exposed to the guest are the same as in the selected instance type.
/// This parameter has been deprecated and it will be removed in future Firecracker
/// release
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum CpuTemplate {
    C3,
    T2,
    T2S,
    T2CL,
    T2A,
    V1N1,
    #[default]
    None,
}

/// The CPU configuration template defines a set of bit maps as modifiers of flags accessed by register
/// to be disabled/enabled for the microvm.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuConfig {
    /// A collection of KVM capabilities to be added or removed (both x86_64 and aarch64)
    ///
    /// KVM capability as a numeric string. Prefix with '!' to remove capability. Example "121" (add) or "!121" (remove)
    pub kvm_capabilities: Option<Vec<String>>,
    /// A collection of CPUID leaf modifiers (x86_64 only)
    pub cpuid_modifiers: Option<Vec<CpuidLeafModifier>>,
    /// A collection of model specific register modifiers (x86_64 only)
    pub msr_modifiers: Option<Vec<MsrModifier>>,
    /// A collection of register modifiers (aarch64 only)
    pub reg_modifiers: Option<Vec<ArmRegisterModifier>>,
    /// A collection of vCPU features to be modified (aarch64 only)
    pub vcpu_features: Option<Vec<VcpuFeatures>>,
}

/// Modifier for a CPUID leaf and subleaf (x86_64)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuidLeafModifier {
    /// CPUID leaf index as hex, binary, or decimal string (e.g., "0x0", "0b0", "0"))
    pub leaf: String,
    /// CPUID subleaf index as hex, binary, or decimal string (e.g., "0x0", "0b0", "0")
    pub subleaf: String,
    /// KVM feature flags for this leaf-subleaf
    pub flags: i32,
    /// Register modifiers for this CPUID leaf
    pub modifiers: Vec<CpuidRegisterModifier>,
}

/// Modifier for a specific CPUID register within a leaf (x86_64)
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuidRegisterModifier {
    /// Target CPUID register name
    pub register: CpuidRegisterName,
    /// 32-bit bitmap string defining which bits to modify. Format is "0b" followed by 32 characters where '0' = clear bit, '1' = set bit, 'x' = don't modify. Example "0b00000000000000000000000000000001" or "0bxxxxxxxxxxxxxxxxxxxxxxxxxxxx0001"
    pub bitmap: String,
}

/// CPUID register name
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CpuidRegisterName {
    #[serde(rename = "eax")]
    Eax,
    #[serde(rename = "ebx")]
    Ebx,
    #[serde(rename = "ecx")]
    Ecx,
    #[serde(rename = "edx")]
    Edx,
}

/// Modifier for a model specific register (x86_64)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsrModifier {
    /// 32-bit MSR address as hex, binary, or decimal string (e.g., "0x10a", "0b100001010", "266")
    pub addr: String,
    /// 64-bit bitmap string defining which bits to modify. Format is "0b" followed by 64 characters where '0' = clear bit, '1' = set bit, 'x' = don't modify. Underscores can be used for readability. Example "0b0000000000000000000000000000000000000000000000000000000000000001"
    pub bitmap: String,
}

/// Modifier for an ARM register (aarch64)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmRegisterModifier {
    /// 64-bit register address as hex, binary, or decimal string (e.g., "0x0", "0b0", "0")
    pub addr: String,
    /// 128-bit bitmap string defining which bits to modify. Format is "0b" followed by up to 128 characters where '0' = clear bit, '1' = set bit, 'x' = don't modify. Underscores can be used for readability. Example "0b0000000000000000000000000000000000000000000000000000000000000001"
    pub bitmap: String,
}

/// vCPU feature modifier (aarch64)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcpuFeatures {
    /// Index in the kvm_vcpu_init.features array
    pub index: i32,
    /// 32-bit bitmap string defining which bits to modify. Format is "0b" followed by 32 characters where '0' = clear bit, '1' = set bit, 'x' = don't modify. Example "0b00000000000000000000000001100000"
    pub bitmap: String,
}

/// Boot source descriptor
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootSource {
    /// Kernel boot arguments
    pub boot_args: Option<String>,
    /// Host level path to the initrd image used to boot the guest
    pub initrd_path: Option<String>,
    /// Host level path to the kernel image used to boot the guest
    pub kernel_image_path: String,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Drive {
    /// Drive id
    pub drive_id: String,
    /// Represents the unique id of the boot partition of this device. It is
    /// optional and it will be taken into account only if the is_root_device
    /// field is true.
    pub partuuid: Option<String>,
    /// Is root device
    pub is_root_device: bool,
    /// Represents the caching strategy for the block device
    pub cache_type: Option<CacheType>,
    /// Is block read only.
    /// This field is required for virtio-block config and should be omitted for vhost-user-block configuration
    pub is_read_only: Option<bool>,
    /// Host level path for the guest drive
    /// This field is required for virtio-block config and should be omitted for vhost-user-block configuration
    pub path_on_host: Option<String>,
    /// Rate limiter configuration
    pub rate_limiter: Option<RateLimiter>,
    /// Type of the IO engine used by the device. "Async" is supported on
    /// host kernels newer than 5.10.51
    /// This field is optional for virtio-block config and should be omitted for vhost-user-block configuration
    pub io_engine: Option<IoEngine>,
    /// Path to the socket of vhost-user-block backend
    /// This field is required for vhost-user-block config should be omitted for virtio-block configuration
    pub socket: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CacheType {
    #[serde(rename = "Unsafe")]
    Unsafe,
    #[serde(rename = "Writeback")]
    Writeback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IoEngine {
    #[serde(rename = "Sync")]
    Sync,
    #[serde(rename = "Async")]
    Async,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pmem {
    /// Identificator for this device
    pub id: String,
    /// Host level path for the virtio-pmem device to use as a backing file
    pub path_on_host: String,
    /// Flag to make this device be the root device for VM boot
    ///
    /// Setting this flag will fail if there is another device configured to be a root device already
    pub root_device: Option<bool>,
    /// Flag to map backing file in read-only mode
    pub read_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Error {
    /// A description of the error condition
    pub fault_message: String,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FullVmConfiguration {
    pub balloon: Option<Balloon>,
    pub drives: Option<Vec<Drive>>,
    #[serde(rename = "boot-source")]
    pub boot_source: Option<BootSource>,
    #[serde(rename = "cpu-config")]
    pub cpu_config: Option<CpuConfig>,
    pub logger: Option<Logger>,
    #[serde(rename = "machine-config")]
    pub machine_config: Option<MachineConfiguration>,
    pub metrics: Option<Metrics>,
    #[serde(rename = "memory-hotplug")]
    pub memory_hotplug: Option<MemoryHotplugConfig>,
    #[serde(rename = "mmds-config")]
    pub mmds_config: Option<MmdsConfig>,
    #[serde(rename = "network-interfaces")]
    pub network_interfaces: Option<Vec<NetworkInterface>>,
    pub pmem: Option<Vec<Pmem>>,
    pub vsock: Option<Vsock>,
    pub entropy: Option<EntropyDevice>,
}

/// Variant wrapper containing the real action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceActionInfo {
    pub action_type: ActionType,
}

/// Enumeration indicating what type of action is contained in the payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    #[serde(rename = "FlushMetrics")]
    FlushMetrics,
    #[serde(rename = "InstanceStart")]
    InstanceStart,
    #[serde(rename = "SendCtrlAltDel")]
    SendCtrlAltDel,
}

/// Describes MicroVM instance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceInfo {
    /// Application name
    pub app_name: String,
    /// Instance id
    pub id: String,
    /// The current detailed state (Not started, Running, Paused) of the Firecracker instance
    pub state: InstanceState,
    /// MicroVM hypervisor build version
    pub vmm_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InstanceState {
    #[serde(rename = "Not Started")]
    NotStarted,
    Running,
    Paused,
    Stopped,
}

impl std::fmt::Display for InstanceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstanceState::NotStarted => write!(f, "Not Started"),
            InstanceState::Running => write!(f, "Running"),
            InstanceState::Paused => write!(f, "Paused"),
            InstanceState::Stopped => write!(f, "Stopped"),
        }
    }
}

/// Describes the configuration option for the logging capability
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Logger {
    /// Set the level. The possible values are case-insensitive
    pub level: Option<LoggerLevel>,
    /// Path to the named pipe or file for the human readable log output
    pub log_path: Option<String>,
    /// Whether or not to output the level in the logs
    pub show_level: Option<String>,
    /// Whether or not to include the file path and line number of the log's origin
    pub show_log_origin: Option<String>,
    /// The module path to filter log messages by, example: `api_server::request`
    pub module: Option<String>,
}

/// INFO: Logger level is case-insensitive
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum LoggerLevel {
    #[serde(rename = "Error")]
    Error,
    #[serde(rename = "Warning")]
    Warning,
    #[serde(rename = "Info")]
    #[default]
    Info,
    #[serde(rename = "Debug")]
    Debug,
    #[serde(rename = "Trace")]
    Trace,
    #[serde(rename = "Off")]
    Off,
}

// We only need to transform it into string
impl Display for LoggerLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoggerLevel::Error => write!(f, "Error"),
            LoggerLevel::Warning => write!(f, "Warning"),
            LoggerLevel::Info => write!(f, "Info"),
            LoggerLevel::Debug => write!(f, "Debug"),
            LoggerLevel::Trace => write!(f, "Trace"),
            LoggerLevel::Off => write!(f, "Off"),
        }
    }
}

/// Defines a vsock device, backed by a set of Unix Domain Sockets, on the host side.
/// For host-initiated connections, Firecracker will be listening on the Unix socket
/// identified by the path `uds_path`. Firecracker will create this socket, bind and
/// listen on it. Host-initiated connections will be performed by connection to this
/// socket and issuing a connection forwarding request to the desired guest-side vsock
/// port (i.e. `CONNECT 52\n`, to connect to port 52).
/// For guest-initiated connections, Firecracker will expect host software to be
/// bound and listening on Unix sockets at `uds_path_<PORT>`.
/// E.g. "/path/to/host_vsock.sock_52" for port number 52.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Vsock {
    /// Guest Vsock CID
    pub guest_cid: isize,
    /// Path to UNIX domain socket, used to proxy vsock connections
    pub uds_path: String,
    /// This parameter has been deprecated and it will be removed in future Firecracker release
    pub vsock_id: Option<String>,
}

/// The status of the hotpluggable memory device (virtio-mem)
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryHotplugStatus {
    /// Total size of the hotpluggable memory in MiB
    pub total_size_mib: Option<isize>,
    /// Slot size for the hotpluggable memory in MiB
    pub slot_size_mib: Option<isize>,
    /// (Logical) Block size for the hotpluggable memory in MiB
    pub block_size_mib: Option<isize>,
    /// Plugged size for the hotpluggable memory in MiB
    pub plugged_size_mib: Option<isize>,
    /// Requested size for the hotpluggable memory in MiB
    pub requested_size_mib: Option<isize>,
}

/// Describes the Firecracker version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirecrackerVersion {
    /// Firecracker build version
    pub firecracker_version: String,
}

/// An update to the size of the hotpluggable memory region
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryHotplugSizeUpdate {
    /// New target region size
    pub requested_size_mib: Option<isize>,
}

/// The configuration of the serial device
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialDevice {
    /// Path to a file or named pipe on the host to which serial output should be written
    pub serial_out_path: Option<String>,
}

/// The configuration of the hotpluggable memory device (virtio-mem)
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryHotplugConfig {
    /// Total size of the hotpluggable memory in MiB
    pub total_size_mib: Option<isize>,
    /// Slot size for the hotpluggable memory in MiB. This will determine the granularity of
    /// hot-plug memory from the host. Refer to the device documentation on how to tune this value
    pub slot_size_mib: Option<isize>,
    /// (Logical) Block size for the hotpluggable memory in MiB. This will determine the logical
    /// granularity of hot-plug memory for the guest. Refer to the device documentation on how to tune this value
    pub block_size_mib: Option<isize>,
}

/// Defines an entropy device
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyDevice {
    pub rate_limiter: Option<RateLimiter>,
}

/// Defines a network interface
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub guest_mac: Option<String>,
    /// Host level path for the guest network interface
    pub host_dev_name: String,
    pub iface_id: String,
    pub rx_rate_limiter: Option<RateLimiter>,
    pub tx_rate_limiter: Option<RateLimiter>,
}

/// Describes the contents of MMDS in JSON format
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmdsContentsObject {
    #[serde(flatten)]
    pub contents: Value,
}

/// Describes the configuration option for the metrics capability.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    /// Path to the named pipe or file where the JSON-formatted metrics are flushed
    pub metrics_path: String,
}

/// Describes the number of vCPUs, memory size, SMT capabilities, huge page configuration and the CPU template
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineConfiguration {
    pub cpu_template: Option<CpuTemplate>,
    /// Flag for enabling/disabling simultaneous multithreading. Can be enabled only on x86.
    pub smt: Option<bool>,
    /// Memory size of VM
    pub mem_size_mib: isize,
    /// Enable dirty page tracking. If this is enabled, then incremental guest memory
    /// snapshots can be created. These belong to diff snapshots, which contain, besides
    /// the microVM state, only the memory dirtied since a previous snapshot. Full snapshots
    /// each contain a full copy of the guest memory.
    pub track_dirty_pages: Option<bool>,
    /// Number of vCPUs (either 1 or an even number) (1 <= n <= 32)
    pub vcpu_count: isize,
    /// Which huge pages configuration (if any) should be used to back guest memory
    pub huge_pages: Option<HugePages>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HugePages {
    #[serde(rename = "None")]
    None,
    #[serde(rename = "2M")]
    TwoM,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryBackendType {
    #[serde(rename = "File")]
    File,
    #[serde(rename = "Uffd")]
    Uffd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBackend {
    pub backend_type: MemoryBackendType,
    /// Based on 'backend_type' it is either
    /// 1) Path to the file that contains the guest memory to be loaded
    /// 2) Path to the UDS where a process is listening for a UFFD initialization
    /// control payload and open file descriptor that it can use to serve this
    /// process's guest memory page faults
    pub backend_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum MmdsConfigVersion {
    #[serde(rename = "V1")]
    V1,
    #[serde(rename = "V2")]
    #[default]
    V2,
}

/// Defines the MMDS configuration
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmdsConfig {
    /// Enumeration indicating the MMDS version to be configured
    pub version: Option<MmdsConfigVersion>,
    /// List of the network interface IDs capable of forwarding packets to
    /// the MMDS. Network interface IDs mentioned must be valid at the time
    /// of this request. The net device model will reply to HTTP GET requests
    /// sent to the MMDS address via the interfaces mentioned. In this
    /// case, both ARP requests and TCP segments heading to `ipv4_address`
    /// are intercepted by the device model, and do not reach the associated
    /// TAP device.
    pub network_interfaces: Vec<String>,
    /// A valid IPv4 link-local address
    pub ipv4_address: Option<String>,
    /// MMDS operates compatibly with EC2 IMDS (i.e. responds "text/plain"
    /// content regardless of Accept header in requests)
    pub imds_compat: Option<bool>,
}

/// Defines an IO rate limiter with independent bytes/s and ops/s limits
/// Limits are defined by configuring each of the _bandwidth_ and _ops_ token buckets
/// This field is optional for virtio-block config and should be omitted for vhost-user-block configuration
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiter {
    /// Token bucket with bytes as tokens
    pub bandwidth: Option<TokenBucket>,
    /// Token bucket with operations as tokens
    pub ops: Option<TokenBucket>,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotCreateParams {
    /// Type of snapshot to create. It is optional and by default, a full snapshot is created
    pub snapshot_type: Option<SnapshotType>,
    /// Path to the file that will contain the guest memory
    pub mem_file_path: String,
    /// Path to the file that will contain the microVM state
    pub snapshot_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SnapshotType {
    #[serde(rename = "Full")]
    Full,
    #[serde(rename = "Diff")]
    Diff,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialDrive {
    pub drive_id: String,
    /// Host level path for the guest drive
    ///
    /// This field is optional for virtio-block config and should be omitted for vhost-user-block configuration
    pub path_on_host: Option<String>,
    pub rate_limiter: Option<RateLimiter>,
}

/// Defines a partial network interface structure, used to update the rate limiters for that interface, after microvm start
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialNetworkInterface {
    pub iface_id: String,
    pub rx_rate_limiter: Option<RateLimiter>,
    pub tx_rate_limiter: Option<RateLimiter>,
}

/// Defines a token bucket with a maximum capacity (size), an initial burst size
/// (one_time_burst) and an interval for refilling purposes (refill_time).
/// The refill-rate is derived from size and refill_time, and it is the constant
/// rate at which the tokens replenish. The refill process only starts happening after
/// the initial burst budget is consumed.
/// Consumption from the token bucket is unbounded in speed which allows for bursts
/// bound in size by the amount of tokens available.
/// Once the token bucket is empty, consumption speed is bound by the refill_rate.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBucket {
    /// The initial size of a token bucket
    pub one_time_burst: Option<i64>,
    /// The amount of milliseconds it takes for the bucket to refill
    pub refill_time: i64,
    /// The total number of tokens this bucket can hold
    pub size: i64,
}

/// Allows for changing the backing TAP device of a network interface during snapshot restore
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkOverride {
    /// The name of the interface to modify
    pub iface_id: String,
    /// The new host device of the interface
    pub host_dev_name: String,
}

/// Defines the configuration used for handling snapshot resume. Exactly one of
/// the two `mem_*` fields must be present in the body of the request.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotLoadParams {
    /// (Deprecated) Enable dirty page tracking to improve space efficiency of diff snapshots
    pub enable_diff_snapshots: Option<bool>,
    /// Enable dirty page tracking to improve space efficiency of diff snapshots
    pub track_dirty_pages: Option<bool>,
    /// Path to the file that contains the guest memory to be loaded.
    /// It is only allowed if `mem_backend` is not present. This parameter has
    /// been deprecated and it will be removed in future Firecracker release.
    pub mem_file_path: Option<String>,
    /// Configuration for the backend that handles memory load. If this field
    /// is specified, `mem_file_path` is forbidden. Either `mem_backend` or
    /// `mem_file_path` must be present at a time.
    pub mem_backend: Option<MemoryBackend>,
    /// Path to the file that contains the microVM state to be loaded
    pub snapshot_path: String,
    /// When set to true, the vm is also resumed if the snapshot load is successful
    pub resume_vm: Option<bool>,
    /// Network host device names to override
    pub network_overrides: Option<Vec<NetworkOverride>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VmState {
    #[serde(rename = "Paused")]
    Paused,
    #[serde(rename = "Running")]
    Running,
}
