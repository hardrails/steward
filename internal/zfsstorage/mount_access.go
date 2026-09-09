package zfsstorage

// MountAccess prepares only a newly created or cloned dataset root and verifies
// retained roots on inspection. No tenant request selects a UID, GID or mode.
type MountAccess interface {
	Prepare(string) error
	Verify(string) error
}

// FilesystemMountAccess keeps the root owned by the privileged worker, grants
// the fixed sandbox group access, and denies all other users. Workloads can
// create files but cannot chmod or chown the dataset root itself.
type FilesystemMountAccess struct{}
