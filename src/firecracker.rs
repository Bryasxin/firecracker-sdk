use crate::api::ApiError;
use crate::dto::{
    ActionType, Balloon, BootSource, Drive, InstanceActionInfo, InstanceInfo, InstanceState,
    MachineConfiguration, NetworkInterface, Pmem, VmState, Vsock,
};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::{Child, Command};
use tokio::time::{Duration, timeout};
use tracing::{debug, error, info, instrument, warn};

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
        info!("setting boot source");
        self.config.boot_source = Some(boot_source);
        Ok(())
    }

    /// Set machine configuration
    pub fn set_machine_config(
        &mut self,
        machine_config: MachineConfiguration,
    ) -> Result<(), Error> {
        self.ensure_not_started()?;
        info!("setting machine configuration");
        self.config.machine_config = Some(machine_config);
        Ok(())
    }

    /// Add drive
    pub fn add_drive(&mut self, drive: Drive) -> Result<(), Error> {
        self.ensure_not_started()?;
        info!(drive_id = %drive.drive_id, "adding drive");
        self.config.drives.push(drive);
        Ok(())
    }

    /// Add network interface
    pub fn add_network(&mut self, network: NetworkInterface) -> Result<(), Error> {
        self.ensure_not_started()?;
        info!(iface_id = %network.iface_id, "adding network interface");
        self.config.networks.push(network);
        Ok(())
    }

    /// Add PMEM
    pub fn add_pmem(&mut self, pmem: Pmem) -> Result<(), Error> {
        self.ensure_not_started()?;
        info!(pmem_id = %pmem.id, "adding PMEM device");
        self.config.pmems.push(pmem);
        Ok(())
    }

    /// Set VSock
    pub fn set_vsock(&mut self, vsock: Vsock) -> Result<(), Error> {
        self.ensure_not_started()?;
        info!("setting VSock device");
        self.config.vsock = Some(vsock);
        Ok(())
    }

    /// Set balloon
    pub fn set_balloon(&mut self, balloon: Balloon) -> Result<(), Error> {
        self.ensure_not_started()?;
        info!("setting balloon device");
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
    #[instrument(skip(self))]
    async fn apply_config(&self) -> Result<(), Error> {
        let client = self.client.as_ref().ok_or_else(|| {
            error!("API client not available for configuration");
            Error::InvalidState(format!(
                "expected state with API client, found {}",
                self.state
            ))
        })?;

        info!("applying VM configuration");

        if let Some(boot_source) = &self.config.boot_source {
            info!("configuring boot source");
            if let Err(e) = client.put_boot_source(boot_source).await {
                error!(error = %e, "failed to configure boot source");
                return Err(e.into());
            }
        }

        if let Some(machine_config) = &self.config.machine_config {
            info!("configuring machine settings");
            if let Err(e) = client.put_machine_config(machine_config).await {
                error!(error = %e, "failed to configure machine settings");
                return Err(e.into());
            }
        }

        if !self.config.drives.is_empty() {
            info!(count = self.config.drives.len(), "configuring drives");
            for drive in &self.config.drives {
                if let Err(e) = client.put_drives(drive).await {
                    error!(drive_id = %drive.drive_id, error = %e, "failed to configure drive");
                    return Err(e.into());
                }
            }
        }

        if !self.config.networks.is_empty() {
            info!(
                count = self.config.networks.len(),
                "configuring network interfaces"
            );
            for network in &self.config.networks {
                if let Err(e) = client.put_network_interface(network).await {
                    error!(iface_id = %network.iface_id, error = %e, "failed to configure network interface");
                    return Err(e.into());
                }
            }
        }

        if !self.config.pmems.is_empty() {
            info!(count = self.config.pmems.len(), "configuring PMEM devices");
            for pmem in &self.config.pmems {
                if let Err(e) = client.put_pmem(pmem).await {
                    error!(pmem_id = %pmem.id, error = %e, "failed to configure PMEM device");
                    return Err(e.into());
                }
            }
        }

        if let Some(vsock) = &self.config.vsock {
            info!("configuring VSock device");
            if let Err(e) = client.put_vsock(vsock).await {
                error!(error = %e, "failed to configure VSock device");
                return Err(e.into());
            }
        }

        if let Some(balloon) = &self.config.balloon {
            info!("configuring balloon device");
            if let Err(e) = client.put_balloon(balloon).await {
                error!(error = %e, "failed to configure balloon device");
                return Err(e.into());
            }
        }

        info!("VM configuration applied successfully");
        Ok(())
    }

    #[instrument(skip(self, api_socket), fields(state = ?self.state))]
    pub async fn start(&mut self, api_socket: impl Into<PathBuf>) -> Result<(), Error> {
        if self.state != InstanceState::NotStarted {
            warn!(
                current_state = %self.state,
                "cannot start Firecracker: invalid state"
            );
            return Err(Error::InvalidState(format!(
                "expected NotStarted, found {}",
                self.state
            )));
        }

        let api_socket = api_socket.into();
        info!(
            binary = %self.firecracker_binary.display(),
            socket = %api_socket.display(),
            "starting Firecracker instance"
        );

        let child = match Command::new(&self.firecracker_binary)
            .args(&self.args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => {
                info!("Firecracker process spawned successfully");
                c
            }
            Err(e) => {
                error!(error = %e, "failed to spawn Firecracker process");
                return Err(e.into());
            }
        };

        debug!("waiting for API socket connection");
        match timeout(Duration::from_secs(5), async {
            loop {
                match tokio::net::UnixStream::connect(&api_socket).await {
                    Ok(_) => break,
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
        })
        .await
        {
            Ok(_) => info!("API socket connected"),
            Err(_) => {
                error!("API socket connection timeout after 5 seconds");
                return Err(Error::InvalidState(format!(
                    "API socket connection timeout: {:?}",
                    api_socket
                )));
            }
        }

        let client = crate::api::FirecrackerApiClient::new(api_socket);
        let instance_info = match client.get_instance_info().await {
            Ok(info) => {
                info!(id = %info.id, state = %info.state, "retrieved instance info");
                info
            }
            Err(e) => {
                error!(error = %e, "failed to get instance info");
                return Err(e.into());
            }
        };

        self.client = Some(client);
        self.process = Some(child);
        self.instance_info = Some(instance_info);

        info!("applying configuration");
        if let Err(e) = self.apply_config().await {
            error!(error = %e, "failed to apply configuration");
            return Err(e);
        }
        info!("configuration applied successfully");

        info!("sending InstanceStart action");
        match self
            .client
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
            .await
        {
            Ok(_) => info!("InstanceStart action completed"),
            Err(e) => {
                error!(error = %e, "failed to start instance");
                return Err(e.into());
            }
        }

        self.state = InstanceState::Running;
        info!("Firecracker instance started successfully");

        Ok(())
    }

    #[instrument(skip(self), fields(state = ?self.state))]
    pub async fn pause(&mut self) -> Result<(), Error> {
        if self.state == InstanceState::Stopped {
            warn!("cannot pause stopped VM");
            return Err(Error::InvalidState(format!(
                "cannot pause stopped VM, current state: {}",
                self.state
            )));
        }
        if self.state != InstanceState::Running {
            warn!(
                current_state = %self.state,
                "cannot pause VM: not in Running state"
            );
            return Err(Error::InvalidState(format!(
                "expected Running, found {}",
                self.state
            )));
        }

        let client = self.client.as_ref().ok_or_else(|| {
            error!("API client not available");
            Error::InvalidState(format!(
                "expected state with API client, found {}",
                self.state
            ))
        })?;

        info!("pausing Firecracker instance");
        match client.patch_vm(&VmState::Paused).await {
            Ok(_) => {
                self.state = InstanceState::Paused;
                info!("Firecracker instance paused successfully");
                Ok(())
            }
            Err(e) => {
                error!(error = %e, "failed to pause instance");
                Err(e.into())
            }
        }
    }

    #[instrument(skip(self), fields(state = ?self.state))]
    pub async fn resume(&mut self) -> Result<(), Error> {
        if self.state == InstanceState::Stopped {
            warn!("cannot resume stopped VM");
            return Err(Error::InvalidState(format!(
                "cannot resume stopped VM, current state: {}",
                self.state
            )));
        }
        if self.state != InstanceState::Paused {
            warn!(
                current_state = %self.state,
                "cannot resume VM: not in Paused state"
            );
            return Err(Error::InvalidState(format!(
                "expected Paused, found {}",
                self.state
            )));
        }

        let client = self.client.as_ref().ok_or_else(|| {
            error!("API client not available");
            Error::InvalidState(format!(
                "expected state with API client, found {}",
                self.state
            ))
        })?;

        info!("resuming Firecracker instance");
        match client.patch_vm(&VmState::Running).await {
            Ok(_) => {
                self.state = InstanceState::Running;
                info!("Firecracker instance resumed successfully");
                Ok(())
            }
            Err(e) => {
                error!(error = %e, "failed to resume instance");
                Err(e.into())
            }
        }
    }

    #[instrument(skip(self), fields(state = ?self.state))]
    pub async fn shutdown(&mut self) -> Result<(), Error> {
        info!("shutting down Firecracker instance");

        if let Some(client) = &self.client {
            debug!("sending CtrlAltDel action");
            if let Err(e) = client
                .put_actions(&InstanceActionInfo {
                    action_type: ActionType::SendCtrlAltDel,
                })
                .await
            {
                warn!(error = %e, "failed to send CtrlAltDel action");
            }
        }

        // Wait for process to exit to avoid zombie processes
        if let Some(mut process) = self.process.take() {
            debug!("killing Firecracker process");
            if let Err(e) = process.kill().await {
                warn!(error = %e, "failed to kill process");
            }
            let _ = timeout(Duration::from_secs(5), process.wait()).await;
        }

        self.client = None;
        self.process = None;
        self.state = InstanceState::Stopped;
        self.instance_info = None;

        info!("Firecracker instance shutdown complete");
        Ok(())
    }
}

impl Drop for Firecracker {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            debug!("dropping Firecracker instance, killing process");
            if let Err(e) = process.start_kill() {
                warn!(error = %e, "failed to kill process during drop");
            }
        }
    }
}
