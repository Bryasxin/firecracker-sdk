use crate::api::ApiError;
use crate::dto::{
    ActionType, Balloon, BootSource, Drive, InstanceActionInfo, InstanceInfo, InstanceState,
    MachineConfiguration, NetworkInterface, Pmem, VmState, Vsock,
};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::{Child, Command};
use tokio::time::{Duration, timeout};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to spawn Firecracker process: {0}")]
    Process(#[from] std::io::Error),

    #[error("API error: {0}")]
    Api(#[from] ApiError),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
}

#[derive(Debug, Default, Clone)]
struct FirecrackerConfig {
    boot_source: Option<BootSource>,
    machine_config: Option<MachineConfiguration>,
    drives: Vec<Drive>,
    networks: Vec<NetworkInterface>,
    pmems: Vec<Pmem>,
    vsock: Option<Vsock>,
    balloon: Option<Balloon>,
}

/// Firecracker wrapper, you should use [`crate::FirecrackerBuilder`] to create it.
#[derive(Debug)]
pub struct Firecracker {
    firecracker_binary: PathBuf,
    args: Vec<String>,
    client: Option<crate::api::FirecrackerApiClient>,
    process: Option<Child>,
    state: InstanceState,
    config: FirecrackerConfig,
    instance_info: Option<InstanceInfo>,
}

impl Firecracker {
    pub(crate) fn new(firecracker_binary: PathBuf) -> Self {
        Self {
            firecracker_binary,
            args: Vec::new(),
            client: None,
            process: None,
            state: InstanceState::NotStarted,
            config: FirecrackerConfig::default(),
            instance_info: None,
        }
    }

    /// Get instance state
    pub fn state(&self) -> InstanceState {
        self.state.clone()
    }

    /// Get instance information
    pub fn instance_info(&self) -> Option<&InstanceInfo> {
        self.instance_info.as_ref()
    }

    /// Get API client
    ///
    /// Warn: before using this method, you should know what you are doing.
    pub fn api(&self) -> Result<&crate::api::FirecrackerApiClient, Error> {
        self.client.as_ref().ok_or_else(|| {
            Error::InvalidState(format!(
                "expected state with API client, found {}",
                self.state
            ))
        })
    }

    /// Ensure state is [`InstanceState::NotStarted`]
    fn ensure_not_started(&self) -> Result<(), Error> {
        match self.state {
            InstanceState::NotStarted => Ok(()),
            _ => Err(Error::InvalidState(format!(
                "expected NotStarted, found {}",
                self.state
            ))),
        }
    }

    /// Set boot source
    pub fn set_boot_source(&mut self, boot_source: BootSource) -> Result<(), Error> {
        self.ensure_not_started()?;
        self.config.boot_source = Some(boot_source);
        Ok(())
    }

    /// Set machine configuration
    pub fn set_machine_config(
        &mut self,
        machine_config: MachineConfiguration,
    ) -> Result<(), Error> {
        self.ensure_not_started()?;
        self.config.machine_config = Some(machine_config);
        Ok(())
    }

    /// Add drive
    pub fn add_drive(&mut self, drive: Drive) -> Result<(), Error> {
        self.ensure_not_started()?;
        self.config.drives.push(drive);
        Ok(())
    }

    /// Add network interface
    pub fn add_network(&mut self, network: NetworkInterface) -> Result<(), Error> {
        self.ensure_not_started()?;
        self.config.networks.push(network);
        Ok(())
    }

    /// Add PMEM
    pub fn add_pmem(&mut self, pmem: Pmem) -> Result<(), Error> {
        self.ensure_not_started()?;
        self.config.pmems.push(pmem);
        Ok(())
    }

    /// Set VSock
    pub fn set_vsock(&mut self, vsock: Vsock) -> Result<(), Error> {
        self.ensure_not_started()?;
        self.config.vsock = Some(vsock);
        Ok(())
    }

    /// Set balloon
    pub fn set_balloon(&mut self, balloon: Balloon) -> Result<(), Error> {
        self.ensure_not_started()?;
        self.config.balloon = Some(balloon);
        Ok(())
    }

    /// Add Firecracker process args
    ///
    /// Warn: do not add args after starting instance
    pub(crate) fn add_arg(&mut self, arg: impl Into<String>) {
        self.args.push(arg.into())
    }

    /// Apply configuration via internal API client
    async fn apply_config(&self) -> Result<(), Error> {
        let client = self.client.as_ref().ok_or_else(|| {
            Error::InvalidState(format!(
                "expected state with API client, found {}",
                self.state
            ))
        })?;

        if let Some(boot_source) = &self.config.boot_source {
            client.put_boot_source(boot_source).await?;
        }

        if let Some(machine_config) = &self.config.machine_config {
            client.put_machine_config(machine_config).await?;
        }

        for drive in &self.config.drives {
            client.put_drives(drive).await?;
        }

        for network in &self.config.networks {
            client.put_network_interface(network).await?;
        }

        for pmem in &self.config.pmems {
            client.put_pmem(pmem).await?;
        }

        if let Some(vsock) = &self.config.vsock {
            client.put_vsock(vsock).await?;
        }

        if let Some(balloon) = &self.config.balloon {
            client.put_balloon(balloon).await?;
        }

        Ok(())
    }

    pub async fn start(&mut self, api_socket: impl Into<PathBuf>) -> Result<(), Error> {
        if self.state != InstanceState::NotStarted {
            return Err(Error::InvalidState(format!(
                "expected NotStarted, found {}",
                self.state
            )));
        }

        let api_socket = api_socket.into();
        let child = Command::new(&self.firecracker_binary)
            .args(&self.args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // Wait for API socket
        timeout(Duration::from_secs(5), async {
            loop {
                match tokio::net::UnixStream::connect(&api_socket).await {
                    Ok(_) => break,
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
        })
        .await
        .map_err(|_| {
            Error::InvalidState(format!("API socket connection timeout: {:?}", api_socket))
        })?;

        let client = crate::api::FirecrackerApiClient::new(api_socket);
        let instance_info = client.get_instance_info().await?;

        self.client = Some(client);
        self.process = Some(child);
        self.instance_info = Some(instance_info);

        // Apply user configuration
        self.apply_config().await?;

        // Put `InstanceStart` action
        self.client
            .as_ref()
            .ok_or_else(|| {
                Error::InvalidState(format!(
                    "expected state with API client, found {}",
                    self.state
                ))
            })?
            .put_actions(&InstanceActionInfo {
                action_type: ActionType::InstanceStart,
            })
            .await?;

        self.state = InstanceState::Running;

        Ok(())
    }

    /// Pause Firecracker instance
    pub async fn pause(&mut self) -> Result<(), Error> {
        if self.state == InstanceState::Stopped {
            return Err(Error::InvalidState(format!(
                "cannot pause stopped VM, current state: {}",
                self.state
            )));
        }
        if self.state != InstanceState::Running {
            return Err(Error::InvalidState(format!(
                "expected Running, found {}",
                self.state
            )));
        }

        let client = self.client.as_ref().ok_or_else(|| {
            Error::InvalidState(format!(
                "expected state with API client, found {}",
                self.state
            ))
        })?;

        client.patch_vm(&VmState::Paused).await?;

        self.state = InstanceState::Paused;

        Ok(())
    }

    /// Resume Firecracker instance
    pub async fn resume(&mut self) -> Result<(), Error> {
        if self.state == InstanceState::Stopped {
            return Err(Error::InvalidState(format!(
                "cannot resume stopped VM, current state: {}",
                self.state
            )));
        }
        if self.state != InstanceState::Paused {
            return Err(Error::InvalidState(format!(
                "expected Paused, found {}",
                self.state
            )));
        }

        let client = self.client.as_ref().ok_or_else(|| {
            Error::InvalidState(format!(
                "expected state with API client, found {}",
                self.state
            ))
        })?;

        client.patch_vm(&VmState::Running).await?;

        self.state = InstanceState::Running;

        Ok(())
    }

    /// Shutdown Firecracker
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        if let Some(client) = &self.client {
            let _ = client
                .put_actions(&InstanceActionInfo {
                    action_type: ActionType::SendCtrlAltDel,
                })
                .await;
        }

        // Wait for process to exit to avoid zombie processes
        if let Some(mut process) = self.process.take() {
            let _ = process.kill().await;
            let _ = timeout(Duration::from_secs(5), process.wait()).await;
        }

        self.client = None;
        self.process = None;
        self.state = InstanceState::Stopped;
        self.instance_info = None;

        Ok(())
    }
}

impl Drop for Firecracker {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            let _ = process.start_kill();
        }
    }
}
