using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Renci.SshNet;

namespace PEMStoreSSH.RemoteHandlers
{
    class SSHHandler : BaseRemoteHandler
    {
        private ConnectionInfo Connection { get; set; }

        internal SSHHandler(string server, string serverLogin, string serverPassword)
        {
            if (string.IsNullOrEmpty(server))
                throw new PEMException("Blank or missing server name for server orchestration.");
            if (string.IsNullOrEmpty(serverLogin))
                throw new PEMException("Blank or missing username for server SSH login.");
            if (string.IsNullOrEmpty(serverPassword))
                throw new PEMException("Blank or missing password or SSH key for server SSH login.");


            Server = server;

            List<AuthenticationMethod> authenticationMethods = new List<AuthenticationMethod>();
            if (serverPassword.Length < PASSWORD_LENGTH_MAX)
                authenticationMethods.Add(new PasswordAuthenticationMethod(serverLogin, serverPassword));
            else
                authenticationMethods.Add(new PrivateKeyAuthenticationMethod(serverLogin, new PrivateKeyFile[] { new PrivateKeyFile(new MemoryStream(Encoding.ASCII.GetBytes(ReplaceSpacesWithLF(serverPassword)))) }));

            Connection = new ConnectionInfo(server, serverLogin, authenticationMethods.ToArray());
        }

        public override string RunCommand(string commandText, object[] arguments, bool withSudo, string[] passwordsToMaskInLog)
        {
            Logger.Debug($"RunCommand: {Server}");

            string sudo = $"echo -e '\n' | sudo -S ";
            using (SshClient client = new SshClient(Connection))
            {
                try
                {
                    client.Connect();

                    if (withSudo)
                        commandText = sudo + commandText;

                    string displayCommand = commandText;
                    if (passwordsToMaskInLog != null)
                    {
                        foreach (string password in passwordsToMaskInLog)
                            displayCommand = displayCommand.Replace(password, PASSWORD_MASK_VALUE);
                    }

                    using (SshCommand command = client.CreateCommand($"{commandText}"))
                    {
                        Logger.Debug($"RunCommand: {displayCommand}");
                        command.Execute();
                        Logger.Debug($"SSH Results: {displayCommand}::: {command.Result}::: {command.Error}");
                        return command.Result;
                    }
                }
                finally
                {
                    client.Disconnect();
                }
            }
        }

        public override bool DoesFileExist(string path)
        {
            Logger.Debug($"DoesFileExist: {path}");

            using (SftpClient client = new SftpClient(Connection))
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

        public override void UploadCertificateFile(string path, byte[] certBytes)
        {
            Logger.Debug($"UploadCertificateFile: {path}");

            using (SftpClient client = new SftpClient(Connection))
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

        public override byte[] DownloadCertificateFile(string path, bool hasBinaryContent)
        {
            Logger.Debug($"DownloadCertificateFile: {path}");

            using (SftpClient client = new SftpClient(Connection))
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

        public override void RemoveCertificateFile(string path)
        {
            Logger.Debug($"RemoveCertificateFile: {path}");

            using (SftpClient client = new SftpClient(Connection))
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

        public override void CreateEmptyStoreFile(string path)
        {
            RunCommand($"touch {path}", null, false, null);
            //using sudo will create as root. set useSudo to false 
            //to ensure ownership is with the credentials configued in the platform
        }

        private string ReplaceSpacesWithLF(string privateKey)
        {
            return privateKey.Replace(" RSA PRIVATE ", "^^^").Replace(" ", System.Environment.NewLine).Replace("^^^", " RSA PRIVATE ");
        }

        private string FormatFTPPath(string path)
        {
            return path.Substring(0, 1) == @"/" ? path : @"/" + path.Replace("\\", "/");
        }
    }
}
