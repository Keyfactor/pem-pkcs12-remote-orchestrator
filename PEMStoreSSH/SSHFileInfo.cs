using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEMStoreSSH
{
    class SSHFileInfo
    {
        public enum FileTypeEnum
        {
            Certificate,
            PrivateKey
        }

        public FileTypeEnum FileType { get; set; }
        public string FileContents { get; set; }
        public byte[] FileContentBytes { get; set; }
    }
}
