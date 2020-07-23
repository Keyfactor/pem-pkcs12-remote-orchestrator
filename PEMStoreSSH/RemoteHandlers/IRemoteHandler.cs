namespace PEMStoreSSH.RemoteHandlers
{
    /// <summary>
    /// Defines the interface that must be implemented by the method used to send data across the wire (i.e. SSH or WinRM via PS)
    /// Currently with the dependency on the SSH class, need to look into refactoring to the inerface to allow SSH or WimRM
    /// </summary>
    interface IRemoteHandler
    {
        string RunCommand(string commandText, object[] parameters, bool withSudo, string[] passwordsToMaskInLog);

        bool DoesFileExist(string path);

        void UploadCertificateFile(string path, byte[] certBytes);

        byte[] DownloadCertificateFile(string path, bool hasBinaryContent);

        void RemoveCertificateFile(string path);

        void CreateEmptyStoreFile(string path);
    }
}
