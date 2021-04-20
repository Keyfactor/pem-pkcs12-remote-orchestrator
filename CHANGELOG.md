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