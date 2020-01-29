using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace PEMStoreSSH
{
    interface ICertificateFormatHandler
    {
        bool HasPrivateKey(byte[] certificateBytes, byte[] privateKeyBytes);
        X509Certificate2Collection RetrieveCertificates(byte[] binaryCertificates, string storePassword);
        List<SSHFileInfo> CreateCertificatePacket(string certToAdd, string pfxPassword, string storePassword, bool hasSeparatePrivateKey);
    }
}
