using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace PEMStoreSSH
{
    class PKCS12Handler : ICertificateFormatHandler
    {
        public bool HasPrivateKey(byte[] certificateBytes, byte[] privateKeyBytes)
        {
            return true;
        }

        public X509Certificate2Collection RetrieveCertificates(byte[] binaryCertificates, string storePassword)
        {
            try
            {
                X509Certificate2Collection certCollection = new X509Certificate2Collection();
                certCollection.Import(binaryCertificates, storePassword, X509KeyStorageFlags.Exportable);
                return certCollection;
            }
            catch (Exception ex)
            {
                throw new PEMException($"Error attempting to retrieve certificate chain.", ex);
            }
        }

        public List<SSHFileInfo> CreateCertificatePacket(string certToAdd, string pfxPassword, string storePassword, bool hasSeparatePrivateKey)
        {
            List<SSHFileInfo> fileInfo = new List<SSHFileInfo>();
            Pkcs12Store store;

            using (MemoryStream inStream = new MemoryStream(Convert.FromBase64String(certToAdd)))
            {
                store = new Pkcs12Store(inStream, pfxPassword.ToCharArray());
            }

            using (MemoryStream outStream = new MemoryStream())
            {
                store.Save(outStream, storePassword.ToCharArray(), new Org.BouncyCastle.Security.SecureRandom());
                //using (StreamReader rdr = new StreamReader(outStream))
                //{
                    fileInfo.Add(new SSHFileInfo()
                    {
                        FileType = SSHFileInfo.FileTypeEnum.Certificate,
                        //FileContent = rdr.ReadToEnd(),
                        FileContentBytes = outStream.ToArray()
                    });
                //}
            }

            return fileInfo;
        }
    }
}
