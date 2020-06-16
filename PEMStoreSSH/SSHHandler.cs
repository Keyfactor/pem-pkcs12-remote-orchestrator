using System;
using System.IO;

using Renci.SshNet;
using CSS.Common.Logging;

namespace PEMStoreSSH
{
    class SSHHandler : LoggingClientBase
    {
        public string Server { get; set; }
        public string ServerLogin { get; set; }
        public string ServerPassword { get; set; }

        internal SSHHandler(string server, string serverLogin, string serverPassword)
        {
            Server = server;
            ServerLogin = serverLogin;
            ServerPassword = serverPassword;
        }

        internal string RunCommand(string commandText, bool withSudo)
        {
            Logger.Debug($"RunCommand: {Server}");

            string sudo = $"echo -e '\n' | sudo -S ";
            using (SshClient client = new SshClient(Server, ServerLogin, ServerPassword))
            {
                try
                {
                    client.Connect();

                    if (withSudo)
                        commandText = sudo + commandText;

                    string displayCommand = commandText.Replace(ServerPassword, "[PASSWORD]");

                    using (SshCommand command = client.CreateCommand($"{commandText}"))
                    {
                        Logger.Debug($"RunCommand: {displayCommand}");
                        command.Execute();
                        Logger.Debug($"SSH Results: {displayCommand} {command.Result}");
                        Logger.Debug($"SSH Error: {displayCommand} {command.Error}");
                        return command.Result;
                    }
                }
                catch (Exception ex)
                {
                    throw ex;
                }
                finally
                {
                    client.Disconnect();
                }
            }
        }

        internal bool DoesFileExist(string path)
        {
            Logger.Debug($"DoesFileExist: {path}");


            using (SftpClient client = new SftpClient(Server, ServerLogin, ServerPassword))
            {
                try
                {
                    client.Connect();
                    string existsPath = FormatFTPPath(path);
                    bool exists = client.Exists(existsPath);

                    return exists;
                }
                finally
                {
                    client.Disconnect();
                }
            }
        }

        internal void UploadCertificateFile(string path, byte[] certBytes)
        {
            Logger.Debug($"UploadCertificateFile: {path}");

            using (SftpClient client = new SftpClient(Server, ServerLogin, ServerPassword))
            {
                try
                {
                    client.Connect();

                    using (MemoryStream stream = new MemoryStream(certBytes))
                    {
                        client.UploadFile(stream, FormatFTPPath(path));
                    }
                }
                finally
                {
                    client.Disconnect();
                }
            }
        }

        internal byte[] DownloadCertificateFile(string path)
        {
            Logger.Debug($"DownloadCertificateFile: {path}");

            using (SftpClient client = new SftpClient(Server, ServerLogin, ServerPassword))
            {
                try
                {
                    client.Connect();

                    using (MemoryStream stream = new MemoryStream())
                    {
                        client.DownloadFile(FormatFTPPath(path), stream);
                        return stream.ToArray();
                    }
                }
                finally
                {
                    client.Disconnect();
                }
            }
        }

        internal byte[] DownloadLinuxCertificateFile(string path)
        {
            string certs = RunCommand($"cat {path}", true);
            return System.Text.Encoding.ASCII.GetBytes(certs);
        }

        internal void RemoveCertificateFile(string path)
        {
            Logger.Debug($"RemoveCertificateFile: {path}");

            using (SftpClient client = new SftpClient(Server, ServerLogin, ServerPassword))
            {
                try
                {
                    client.Connect();
                    client.DeleteFile(FormatFTPPath(path));
                }
                finally
                {
                    client.Disconnect();
                }
            }
        }

        private string FormatFTPPath(string path)
        {
            return path.Substring(0, 1) == @"/" ? path : @"/" + path.Replace("\\", "/");
        }
    }
}
