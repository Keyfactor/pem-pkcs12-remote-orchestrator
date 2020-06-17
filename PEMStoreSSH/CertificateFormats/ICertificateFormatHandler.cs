using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace PEMStoreSSH
{
    interface ICertificateFormatHandler
    {
        bool HasPrivateKey(byte[] certificateBytes, byte[] privateKeyBytes);
        X509Certificate2Collection RetrieveCertificates(byte[] binaryCertificates, string storePassword);
        List<SSHFileInfo> CreateCertificatePacket(string certToAdd, string alias, string pfxPassword, string storePassword, bool hasSeparatePrivateKey);
        void AddCertificateToStore(List<SSHFileInfo> files, string storePath, string privateKeyPath, SSHHandler ssh, PEMStore.ServerTypeEnum serverType, bool overwrite, bool hasPrivateKey);
        void RemoveCertificate(PEMStore.ServerTypeEnum serverType, string storePath, string privateKeyPath, SSHHandler ssh, string alias, bool hasPrivateKey);
        bool IsValidStore(string path, SSHHandler ssh);
    }
}
