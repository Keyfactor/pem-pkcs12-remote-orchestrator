v2.4
- Bug fixes for installation on Linux hosted Universal Orchestrator
- Keep file owner/permissions of original certificate store when using separate upload/download folder option

v2.3
- Add new config.json setting DefaultLinuxPermissionsOnStoreCreation, and certificate store type custom parameter linuxFilePermissionsOnStoreCreation
- Add ability to use client machine credentials for WinRM Windows servers rather than always using the Keyfactor service account 

v2.2
- Limit the valid characters that can be used for store paths to protect against command injection.

v2.1
- Add support for SCP protocol for transferring files as an alternative to SFTP

v2.0.2
- Fix sudo usage to take effect when creating cert stores

v2.0
- Upgrade to .Net Core based Universal Orchestrator framework
- Versions >= 2.x will be compatible with the new Keyfactor Universal Orchestrator framework
- Versions < 2.x will continue to traget the Keyfactor Windows Orchestrator

v1.3
- Add config option to use Negotiate when connecting to Windows servers via WinRM
- Updated Renci.SSH.Net reference

v1.2.0:
- Fix issue where adding multiple certificates to an existing store via multiple concurrent Management jobs was causing some certificates to not get added

v1.1.0:
- Add support for alias (friendly) name for PKCS12 certificate stores
- Add local PAM capability for resolving the server password

v1.0.10:
- Modify private key encryption handling so that if a store password is used, the private key of a cert will be encrypted with that password during add operations.  If no store password is set, the private key will be saved without encryption.

v1.0.9:
- Allow for assignment of Store Password which, if present, will be used to encrypt private key in certificate add jobs.

v1.0.8:
- Added new PEM-SSH store type optional property - isSingleCertificateStore.  If this exists and is set to 'True', Management-Add jobs will assume that only one certificate is in the store and will replace entire contents of store with added certificate.  Alias/Thumbprint will NOT be checked before replacing a certificate when this value is set to 'True'.

v1.0.7:
- Added 2 new config entries, UseSeparateUploadFilePath and  SeparateUploadFilePath, to allow for a temporary file upload folder for sftp operations - Linux only

v1.0.6:
- Added ability to perform recursive search on all available local drives on Windows servers by entering "fullscan" in "Directories to Search"

v1.0.5:
- Bug fix: Issue when running Inventory on a certificate store with embedded spaces in the path

v1.0.4:
- Bug fix: Fixed error when running Discovery against a Windows server with a PEM store residing in a path containing an embedded space in one of the folder names.

v1.0.3:
- Added new Y/N config.json item - CreateStoreOnAddIfMissing
- Modified Management-Add process to create empty PEM/PKCS12 storeif CreateStoreOnAddIfMissing = Y
