using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using CSS.Common.Logging;

namespace PEMStoreSSH.RemoteHandlers
{
    abstract class BaseRemoteHandler : LoggingClientBase, IRemoteHandler
    {
        internal const int PASSWORD_LENGTH_MAX = 100;
        internal const string PASSWORD_MASK_VALUE = "[PASSWORD]";

        public string Server { get; set; }

        public abstract string RunCommand(string commandText, object[] parameters, bool withSudo, string[] passwordsToMaskInLog);

        public abstract bool DoesFileExist(string path);

        public abstract void UploadCertificateFile(string path, byte[] certBytes);

        public abstract byte[] DownloadCertificateFile(string path, bool hasBinaryContent);

        public abstract void RemoveCertificateFile(string path);

        public abstract void CreateEmptyStoreFile(string path);

    }
}
