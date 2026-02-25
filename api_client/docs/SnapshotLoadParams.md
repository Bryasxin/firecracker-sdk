# SnapshotLoadParams

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**enable_diff_snapshots** | Option<**bool**> | (Deprecated) Enable dirty page tracking to improve space efficiency of diff snapshots | [optional]
**track_dirty_pages** | Option<**bool**> | Enable dirty page tracking to improve space efficiency of diff snapshots | [optional]
**mem_file_path** | Option<**String**> | Path to the file that contains the guest memory to be loaded. It is only allowed if `mem_backend` is not present. This parameter has been deprecated and it will be removed in future Firecracker release. | [optional]
**mem_backend** | Option<[**models::MemoryBackend**](MemoryBackend.md)> |  | [optional]
**snapshot_path** | **String** | Path to the file that contains the microVM state to be loaded. | 
**resume_vm** | Option<**bool**> | When set to true, the vm is also resumed if the snapshot load is successful. | [optional]
**network_overrides** | Option<[**Vec<models::NetworkOverride>**](NetworkOverride.md)> | Network host device names to override | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


