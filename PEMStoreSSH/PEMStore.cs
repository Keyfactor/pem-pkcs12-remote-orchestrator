using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PEMStoreSSH
{
    internal class PEMStore
    {
        private const string NO_EXTENSION = "noext";

        public enum FormatTypeEnum
        {
            PEM,
            PKCS12
        }

        internal enum ServerTypeEnum
        {
            Linux,
            Windows
        }

        private string Server { get; set; }
        private string ServerId { get; set; }
        private string ServerPassword { get; set; }
        private string StorePath { get; set; }
        private string StorePassword { get; set; }
        private string PrivateKeyPath { get; set; }
        private ICertificateFormatHandler CertificateHandler { get; set; }
        private SSHHandler SSH { get; set; }
        public ServerTypeEnum ServerType { get; set; }


        internal PEMStore(string server, string serverId, string serverPassword, string storeFileAndPath, string storePassword, FormatTypeEnum formatType, string privateKeyPath)
        {
            Server = server;
            StorePath = storeFileAndPath;
            ServerId = serverId;
            ServerPassword = serverPassword;
            StorePassword = storePassword;
            PrivateKeyPath = privateKeyPath;
            CertificateHandler = GetCertificateHandler(formatType);
            ServerType = StorePath.Substring(0, 1) == "/" ? ServerTypeEnum.Linux : ServerTypeEnum.Windows;

           SSH = new SSHHandler(Server, ServerId, ServerPassword);
        }

        internal PEMStore(string server, string serverId, string serverPassword, ServerTypeEnum serverType, FormatTypeEnum formatType)
        {
            Server = server;
            ServerId = serverId;
            ServerPassword = serverPassword;
            ServerType = serverType;
            CertificateHandler = GetCertificateHandler(formatType);

            SSH = new SSHHandler(Server, ServerId, ServerPassword);
        }

        internal bool DoesStoreExist(string path)
        {
            return SSH.DoesFileExist(path);
        }

        internal List<string> FindStores(string[] paths, string[] extensions)
        {
            return ServerType == ServerTypeEnum.Linux ? FindStoresLinux(paths, extensions) : FindStoresWindows(paths, extensions);
        }

        internal X509Certificate2Collection GetCertificates(string storePassword, out bool containsPrivateKey)
        {
            try
            {
                containsPrivateKey = false;

                byte[] certContents = ServerType == ServerTypeEnum.Linux ? SSH.DownloadLinuxCertificateFile(StorePath) : SSH.DownloadCertificateFile(StorePath);

                X509Certificate2Collection certs = CertificateHandler.RetrieveCertificates(certContents, storePassword);
                if (certs.Count >= 1)
                {
                    byte[] privateKeyContentBytes = null;
                    if (!string.IsNullOrEmpty(PrivateKeyPath))
                        privateKeyContentBytes = ServerType == ServerTypeEnum.Linux ? SSH.DownloadLinuxCertificateFile(PrivateKeyPath) : SSH.DownloadCertificateFile(PrivateKeyPath);

                    containsPrivateKey = CertificateHandler.HasPrivateKey(certContents, privateKeyContentBytes);
                }

                return certs;
            }
            catch (Exception ex)
            {
                throw new PEMException($"Error attempting to retrieve certificates for store path={StorePath}.", ex);
            }
        }

        internal void RemoveCertificate()
        {
            try
            {
                SSH.RemoveCertificateFile(StorePath);
            }
            catch (Exception ex)
            {
                throw new PEMException($"Error attempting to remove certificate store {StorePath}.", ex);
            }

            if (!string.IsNullOrEmpty(PrivateKeyPath))
            {
                try
                {
                    SSH.RemoveCertificateFile(PrivateKeyPath);
                }
                catch (Exception ex)
                {
                    throw new PEMException($"Error attempting to remove private key {PrivateKeyPath}.", ex);
                }
            }
        }

        internal void AddCertificateToStore(string cert, string alias, string pfxPassword, string storePassword, bool overwrite, bool containsPrivateKey)
        {
            try
            {
                List<SSHFileInfo> files = CertificateHandler.CreateCertificatePacket(cert, alias, pfxPassword, storePassword, !String.IsNullOrEmpty(PrivateKeyPath));
                CertificateHandler.AddCertificateToStore(files, StorePath, PrivateKeyPath, SSH, ServerType, overwrite, containsPrivateKey);
            }
            catch (Exception ex)
            {
                throw new PEMException($"Error attempting to add certificate to store {StorePath}.", ex);
            }
        }

        internal bool IsValidStore(string path)
        {
            return CertificateHandler.IsValidStore(path, SSH);
        }

        internal void CreateBlankCertificateStore(string path)
        {
            SSH.RunCommand($"touch {path}",false);
            //using sudo will create as root. set useSudo to false 
            //to ensure ownership is with the credentials configued in the platform
        }

        private List<string> FindStoresLinux(string[] paths, string[] extensions)
        {
            try
            {
                string concatPaths = string.Join(" ", paths);
                string command = $"find {concatPaths} ";
                string commandNoExt = $"find {concatPaths} -type f ! -name '*.*'";

                bool searchNoExtension = extensions.Any(p => p == NO_EXTENSION);

                foreach (string extension in extensions)
                {
                    if (extension == NO_EXTENSION)
                        continue;
                    command += (command.IndexOf("-name") == -1 ? string.Empty : "-or ");
                    command += $"-name '*.{extension}' ";
                }

                string result = string.Empty;
                if (extensions.Any(p => p.ToLower() != NO_EXTENSION))
                    result = SSH.RunCommand(command, true);

                if (searchNoExtension)
                    result += ('\n' + SSH.RunCommand(commandNoExt, true));

                return (result.Split(new char[] { '\n' }, StringSplitOptions.RemoveEmptyEntries)).ToList();
            }
            catch (Exception ex)
            {
                throw new PEMException($"Error attempting to find certificate stores for path={string.Join(" ", paths)}.", ex);
            }
        }

        private List<string> FindStoresWindows(string[] paths, string[] extensions)
        {
            List<string> results = new List<string>();
            string concatExtensions = "*." + string.Join(" *.", extensions);

            foreach (string path in paths)
            {
                string command = $"cd {path} && dir {concatExtensions} /s /b ";
                string result = SSH.RunCommand(command, false);
                results.AddRange(result.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries).ToList());
            }

            return results;
        }

        private ICertificateFormatHandler GetCertificateHandler(FormatTypeEnum formatType)
        {
            switch (formatType)
            {
                case FormatTypeEnum.PEM:
                    return new PEMHandler();
                case FormatTypeEnum.PKCS12:
                    return new PKCS12Handler();
                default:
                    throw new Exception("Invalid certificate format:");
            }
        }
    }

    class PEMException : ApplicationException
    {
        public PEMException(string message) : base(message)
        { }

        public PEMException(string message, Exception ex) : base(message, ex)
        { }
    }
}