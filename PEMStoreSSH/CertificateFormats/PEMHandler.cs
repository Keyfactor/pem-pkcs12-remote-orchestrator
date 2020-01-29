using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;

using CSS.PKI.PEM;
using CSS.PKI.PrivateKeys;

namespace PEMStoreSSH
{
    class PEMHandler : ICertificateFormatHandler
    {
        string[] PrivateKeyDelimeters = new string[] { "-----BEGIN PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----" };
        string CertDelimBeg = "-----BEGIN CERTIFICATE-----";
        string CertDelimEnd = "-----END CERTIFICATE-----";

        public bool HasPrivateKey(byte[] certificateBytes, byte[] privateKeyBytes)
        {
            bool rtn = false;

            byte[] compareBytes = privateKeyBytes == null ? certificateBytes : privateKeyBytes;
            string compareContents = Encoding.UTF8.GetString(compareBytes, 0, compareBytes.Length);

            foreach (string delim in PrivateKeyDelimeters)
            {
                if (compareContents.IndexOf(delim, StringComparison.InvariantCultureIgnoreCase) > -1)
                {
                    rtn = true;
                    break;
                }
            }

            return rtn;
        }

        public X509Certificate2Collection RetrieveCertificates(byte[] binaryCertificates, string storePassword)
        {
            try
            {
                X509Certificate2Collection certificateCollection = new X509Certificate2Collection();
                string certificates = Encoding.UTF8.GetString(binaryCertificates);

                while(certificates.Contains(CertDelimBeg))
                {
                    int certStart = certificates.IndexOf(CertDelimBeg);
                    int certLength = certificates.IndexOf(CertDelimEnd) + CertDelimEnd.Length - certStart;
                    certificateCollection.Add(new X509Certificate2(Encoding.UTF8.GetBytes(certificates.Substring(certStart, certLength))));

                    certificates = certificates.Substring(certLength-1);
                }

                return certificateCollection;
            }
            catch (Exception ex)
            {
                throw new PEMException($"Error attempting to retrieve certificate chain.", ex);
            }
        }

        public List<SSHFileInfo> CreateCertificatePacket(string certToAdd, string pfxPassword, string storePassword, bool hasSeparatePrivateKey)
        {
            List<SSHFileInfo> fileInfo = new List<SSHFileInfo>();
            byte[] certBytes = Convert.FromBase64String(certToAdd);

            X509Certificate2 cert = new X509Certificate2(certBytes, pfxPassword);

            byte[] certWithoutKeyBytes = cert.Export(X509ContentType.Cert);
            string certificatePem = PemUtilities.DERToPEM(certWithoutKeyBytes, PemUtilities.PemObjectType.Certificate);

            if (!string.IsNullOrEmpty(pfxPassword))
            {
                PrivateKeyConverter converter = CSS.PKI.PrivateKeys.PrivateKeyConverterFactory.FromPKCS12(certBytes, pfxPassword);
                byte[] privateKeyBytes = converter.ToPkcs8Blob(storePassword);
                string privateKeyPem = PemUtilities.DERToPEM(privateKeyBytes, PemUtilities.PemObjectType.EncryptedPrivateKey);

                if (hasSeparatePrivateKey)
                {
                    fileInfo.Add(new SSHFileInfo()
                    {
                        FileType = SSHFileInfo.FileTypeEnum.Certificate,
                        FileContents = certificatePem
                    });

                    fileInfo.Add(new SSHFileInfo()
                    {
                        FileType = SSHFileInfo.FileTypeEnum.PrivateKey,
                        FileContents = privateKeyPem
                    });
                }
                else
                {
                    fileInfo.Add(new SSHFileInfo()
                    {
                        FileType = SSHFileInfo.FileTypeEnum.Certificate,
                        FileContents = certificatePem + "\n" + privateKeyPem
                    });
                }
            }
            else
            {
                fileInfo.Add(new SSHFileInfo()
                {
                    FileType = SSHFileInfo.FileTypeEnum.Certificate,
                    FileContents = certificatePem
                });
            }

            return fileInfo;
        }

        private void WriteFile(SSHHandler ssh, string path, string contents)
        {

        }
    }
}
