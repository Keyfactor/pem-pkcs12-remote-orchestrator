using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using PEMStoreSSH.RemoteHandlers;

namespace PEMStoreSSH
{
    interface ICertificateFormatHandler
    {
        bool HasPrivateKey(byte[] certificateBytes, byte[] privateKeyBytes);
        X509Certificate2Collection RetrieveCertificates(byte[] binaryCertificates, string storePassword);
        List<SSHFileInfo> CreateCertificatePacket(string certToAdd, string alias, string pfxPassword, string storePassword, bool hasSeparatePrivateKey);
        void AddCertificateToStore(List<SSHFileInfo> files, string storePath, string privateKeyPath, IRemoteHandler ssh, PEMStore.ServerTypeEnum serverType, bool overwrite, bool hasPrivateKey);
        void RemoveCertificate(PEMStore.ServerTypeEnum serverType, string storePath, string privateKeyPath, IRemoteHandler ssh, string alias, bool hasPrivateKey);
        bool IsValidStore(string path, PEMStore.ServerTypeEnum serverType, IRemoteHandler ssh);
        bool HasBinaryContent { get; }
    }
}
