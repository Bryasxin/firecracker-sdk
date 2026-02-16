//! Firecracker API client
use crate::dto;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode, Uri,
    body::{Bytes, Incoming},
};
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, UnixConnector, Uri as UnixUri};
use paste::paste;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct FirecrackerApiClient {
    client: Client<UnixConnector, Full<Bytes>>,
    socket_path: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("HTTP error: {0}")]
    Http(#[from] hyper::http::Error),

    #[error("Transport error: {0}")]
    Transport(#[from] hyper::Error),

    #[error("Request failed: {0}")]
    Request(#[from] hyper_util::client::legacy::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Firecracker API error: {0}")]
    Firecracker(String),
}

impl FirecrackerApiClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            client: Client::unix(),
            socket_path: socket_path.into(),
        }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Full<Bytes>,
    ) -> Result<Response<Incoming>, ApiError> {
        let url: Uri = UnixUri::new(&self.socket_path, path).into();

        let req = Request::builder()
            .method(method)
            .uri(url)
            .header("Content-Type", "application/json")
            .body(body)?;

        let response = self.client.request(req).await?;
        Ok(response)
    }

    async fn parse_response<T>(
        &self,
        response: Response<Incoming>,
        expected_status: StatusCode,
    ) -> Result<T, ApiError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();

        match status {
            s if s == expected_status => {
                let result: T = serde_json::from_slice(&body)?;
                Ok(result)
            }
            StatusCode::BAD_REQUEST => {
                let error: crate::dto::Error = serde_json::from_slice(&body)?;
                Err(ApiError::InvalidInput(error.fault_message))
            }
            _ => {
                let error: crate::dto::Error = serde_json::from_slice(&body)?;
                Err(ApiError::Firecracker(format!(
                    "HTTP {}: {}",
                    status.as_u16(),
                    error.fault_message
                )))
            }
        }
    }

    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    async fn get<T>(&self, path: &str, expected_status: StatusCode) -> Result<T, ApiError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let result = self
            .request(Method::GET, path, Full::new(Bytes::new()))
            .await?;
        self.parse_response(result, expected_status).await
    }

    async fn put<T>(
        &self,
        path: &str,
        req: Vec<u8>,
        expected_status: StatusCode,
    ) -> Result<T, ApiError>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let result = self.request(Method::PUT, path, req.into()).await?;
        self.parse_response(result, expected_status).await
    }

    async fn patch<T>(
        &self,
        path: &str,
        req: Vec<u8>,
        expected_status: StatusCode,
    ) -> Result<T, ApiError>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let result = self.request(Method::PATCH, path, req.into()).await?;
        self.parse_response(result, expected_status).await
    }
}

// TODO: refactor this macro for better readability
macro_rules! api_methods {
    (
        $(
            $method:ident $path:literal
            as $fn_name:ident
            $(-> $ret:tt)?
            $(($param_name:ident: $param:tt))?
            with $status:ident
        );* $(;)?
    ) => {
        impl FirecrackerApiClient {
            $(
                api_methods!(@method
                    $method $path $fn_name
                    $($ret)?
                    $(($param_name $param))?
                    $status
                );
            )*
        }
    };

    // Get
    (@method GET $path:literal $fn_name:ident $ret:tt $status:ident) => {
        pub async fn $fn_name(&self) -> Result<dto::$ret, ApiError> {
            self.get($path, StatusCode::$status).await
        }
    };

    // Put/Patch
    (@method $method:ident $path:literal $fn_name:ident ($param_name:ident $param:tt) $status:ident) => {
        paste! {
            pub async fn $fn_name(
                &self,
                $param_name: &dto::$param,
            ) -> Result<(), ApiError> {
                self.[<$method:lower>](
                    $path,
                    serde_json::to_vec(&$param_name)?,
                    StatusCode::$status,
                )
                .await
            }
        }
    };
}

api_methods!(
    GET "/" as get_instance_info -> InstanceInfo with OK;
    PUT "/actions" as put_actions (action: InstanceActionInfo) with NO_CONTENT;
    GET "/balloon" as get_balloon -> Balloon with OK;
    PUT "/balloon" as put_balloon (balloon: Balloon) with NO_CONTENT;
    PATCH "/balloon" as patch_balloon (balloon_patch: BalloonUpdate) with NO_CONTENT;
    GET "/balloon/statistics" as get_balloon_statistics -> BalloonStats with OK;
    PATCH "/balloon/statistics" as patch_balloon_statistics (balloon_stats_update: BalloonStatsUpdate) with NO_CONTENT;
    PATCH "/balloon/hinting/start" as patch_balloon_hinting_start (balloon_start_cmd: BalloonStartCmd) with OK;
    GET "/balloon/hinting/status" as get_balloon_hinting_status -> BalloonHintingStatus with OK;
    PUT "/boot-source" as put_boot_source (boot_source: BootSource) with NO_CONTENT;
    PUT "/cpu-config" as put_cpu_config (cpu_config: CpuConfig) with NO_CONTENT;
    PUT "/logger" as put_logger (logger: Logger) with NO_CONTENT;
    GET "/machine-config" as get_machine_config -> MachineConfiguration with OK;
    PUT "/machine-config" as put_machine_config (machine_config: MachineConfiguration) with NO_CONTENT;
    PATCH "/machine-config" as patch_machine_config (machine_config: MachineConfiguration) with NO_CONTENT;
    PUT "/metrics" as put_metrics (metrics: Metrics) with NO_CONTENT;
    PUT "/mmds" as put_mmds (mmds: MmdsContentsObject) with NO_CONTENT;
    PATCH "/mmds" as patch_mmds (mmds: MmdsContentsObject) with NO_CONTENT;
    GET "/mmds" as get_mmds -> MmdsContentsObject with OK;
    PUT "/mmds/config" as put_mmds_config (mmds_config: MmdsConfig) with NO_CONTENT;
    PUT "/entropy" as put_entropy (device: EntropyDevice) with NO_CONTENT;
    PUT "/serial" as put_serial (device: SerialDevice) with NO_CONTENT;
    PUT "/hotplug/memory" as put_hotplug_memory(config: MemoryHotplugConfig) with NO_CONTENT;
    PATCH "/hotplug/memory" as patch_hotplug_memory (memory_hotplug_size_update: MemoryHotplugSizeUpdate) with NO_CONTENT;
    GET "/hotplug/memory" as get_hotplug_memory -> MemoryHotplugStatus with OK;
    PUT "/snapshot/create" as put_snapshot_create (options: SnapshotCreateParams) with NO_CONTENT;
    PUT "/snapshot/load" as put_snapshot_load (options: SnapshotLoadParams) with NO_CONTENT;
    GET "/version" as get_version -> FirecrackerVersion with OK;
    PATCH "/vm" as patch_vm (vm: VmState) with NO_CONTENT;
    GET "/vm/config" as get_vm_config -> FullVmConfiguration with OK;
    PUT "/vsock" as put_vsock (vsock: Vsock) with NO_CONTENT;


    // Invalid route, implement manually
    // [*] PATCH "/balloon/hinting/stop" as patch_balloon_hinting_stop with OK;
    //
    // [*] PUT "/drives/{drive_id}" (drive: Drive) with NO_CONTENT;
    // [*] PATCH "/drives/{drive_id}" (partial_drive: PartialDrive) with NO_CONTENT;
    //
    // [*] PUT "/pmem/{id}" (pmem: Pmem) with NO_CONTENT;
    //
    // [*] PUT "/network-interfaces/{iface_id}" (interface: NetworkInterface) with NO_CONTENT;
    // [*] PATCH "/network-interfaces/{iface_id}" (interface: PartialNetworkInterface) with NO_CONTENT;
);

impl FirecrackerApiClient {
    pub async fn patch_balloon_hinting_stop(&self) -> Result<(), ApiError> {
        self.patch("/balloon/hinting/stop", Vec::new(), StatusCode::OK)
            .await
    }

    pub async fn put_drives(&self, drive: &dto::Drive) -> Result<(), ApiError> {
        let encoded_id = utf8_percent_encode(&drive.drive_id, NON_ALPHANUMERIC);
        self.put(
            format!("/drives/{}", encoded_id).as_str(),
            serde_json::to_vec(drive)?,
            StatusCode::NO_CONTENT,
        )
        .await
    }

    pub async fn patch_drives(&self, partial_drive: &dto::PartialDrive) -> Result<(), ApiError> {
        let encoded_id = utf8_percent_encode(&partial_drive.drive_id, NON_ALPHANUMERIC);
        self.patch(
            format!("/drives/{}", encoded_id).as_str(),
            serde_json::to_vec(partial_drive)?,
            StatusCode::NO_CONTENT,
        )
        .await
    }

    pub async fn put_pmem(&self, pmem: &dto::Pmem) -> Result<(), ApiError> {
        let encoded_id = utf8_percent_encode(&pmem.id, NON_ALPHANUMERIC);
        self.put(
            format!("/pmem/{}", encoded_id).as_str(),
            serde_json::to_vec(pmem)?,
            StatusCode::NO_CONTENT,
        )
        .await
    }

    pub async fn put_network_interface(
        &self,
        interface: &dto::NetworkInterface,
    ) -> Result<(), ApiError> {
        let encoded_id = utf8_percent_encode(&interface.iface_id, NON_ALPHANUMERIC);
        self.put(
            format!("/network-interfaces/{}", encoded_id).as_str(),
            serde_json::to_vec(interface)?,
            StatusCode::NO_CONTENT,
        )
        .await
    }

    pub async fn patch_network_interface(
        &self,
        interface: &dto::PartialNetworkInterface,
    ) -> Result<(), ApiError> {
        let encoded_id = utf8_percent_encode(&interface.iface_id, NON_ALPHANUMERIC);
        self.patch(
            format!("/network-interfaces/{}", encoded_id).as_str(),
            serde_json::to_vec(interface)?,
            StatusCode::NO_CONTENT,
        )
        .await
    }
}
