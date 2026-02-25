//! Integration tests for Firecracker SDK
//!
//! These tests require:
//! - Root privileges (for KVM access)
//! - Firecracker binary in PATH
//! - VM kernel and rootfs images in vm/ directory
//!   - Kernel => vm/vmlinux
//!   - Rootfs => vm/rootfs.ext4

#[cfg(test)]
mod tests {
    use firecracker_sdk::{
        FirecrackerBuilder,
        models::drive::CacheType,
        models::{BootSource, Drive, MachineConfiguration},
        types::InstanceState,
    };
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn vm_kernel() -> PathBuf {
        PathBuf::from("vm/vmlinux")
    }

    fn vm_rootfs() -> PathBuf {
        PathBuf::from("vm/rootfs.ext4")
    }

    fn require_vm_images() {
        if !vm_kernel().exists() {
            panic!("VM kernel image not found at {}", vm_kernel().display());
        }
        if !vm_rootfs().exists() {
            panic!("VM rootfs not found at {}", vm_rootfs().display());
        }
    }

    fn build_vm(temp_dir: &TempDir) -> firecracker_sdk::Firecracker {
        let socket_path = temp_dir.path().join("firecracker.sock");

        let mut builder = FirecrackerBuilder::new("firecracker");
        builder.with_api_socket_path(socket_path);

        let mut firecracker = builder.build().expect("Failed to build Firecracker");

        firecracker
            .set_boot_source(BootSource {
                kernel_image_path: vm_kernel().to_string_lossy().to_string(),
                boot_args: Some("console=ttyS0".to_string()),
                initrd_path: None,
            })
            .expect("Failed to set boot source");

        firecracker
            .set_machine_config(MachineConfiguration {
                vcpu_count: 1,
                mem_size_mib: 256,
                smt: None,
                cpu_template: None,
                track_dirty_pages: None,
                huge_pages: None,
            })
            .expect("Failed to set machine config");

        firecracker
            .add_drive(Drive {
                drive_id: "rootfs".to_string(),
                is_root_device: true,
                partuuid: None,
                cache_type: Some(CacheType::Writeback),
                is_read_only: Some(false),
                path_on_host: Some(vm_rootfs().to_string_lossy().to_string()),
                rate_limiter: None,
                io_engine: None,
                socket: None,
            })
            .expect("Failed to add drive");

        firecracker
    }

    #[test]
    fn test_vm_images_exist() {
        require_vm_images();
        assert!(vm_kernel().exists(), "VM kernel missing");
        assert!(vm_rootfs().exists(), "VM rootfs missing");
    }

    #[tokio::test]
    #[ignore = "requires root + KVM"]
    async fn test_vm_lifecycle() {
        require_vm_images();

        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("firecracker.sock");

        let mut firecracker = build_vm(&temp_dir);

        // Test: instance info should be None before start
        assert!(
            firecracker.instance_info().is_none(),
            "Instance info should be None before start"
        );

        // Test: start VM
        firecracker
            .start(socket_path)
            .await
            .expect("Failed to start VM");
        assert_eq!(firecracker.state(), InstanceState::Running);
        assert!(firecracker.instance_info().is_some());
        assert_eq!(
            firecracker.instance_info().unwrap().state,
            firecracker_sdk::models::instance_info::State::Running
        );

        // Test: pause VM
        firecracker.pause().await.expect("Failed to pause VM");
        assert_eq!(firecracker.state(), InstanceState::Paused);

        // Test: resume VM
        firecracker.resume().await.expect("Failed to resume VM");
        assert_eq!(firecracker.state(), InstanceState::Running);

        // Test: start again should fail
        let result = firecracker
            .start(temp_dir.path().join("firecracker2.sock"))
            .await;
        assert!(result.is_err(), "Starting already running VM should fail");

        // Test: shutdown VM
        firecracker.shutdown().await.expect("Failed to shutdown VM");
        assert_eq!(firecracker.state(), InstanceState::Stopped);
    }
}
