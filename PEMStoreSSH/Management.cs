using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;

using Keyfactor.Platform.Extensions.Agents;
using Keyfactor.Platform.Extensions.Agents.Enums;
using Keyfactor.Platform.Extensions.Agents.Delegates;
using Keyfactor.Platform.Extensions.Agents.Interfaces;

using CSS.Common.Logging;

using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;

namespace PEMStoreSSH
{
    public class Management: LoggingClientBase, IAgentJobExtension
    {
        public string GetJobClass()
        {
            return "Management";
        }

        public string GetStoreType()
        {
            return "PEM-SSH";
        }

        public AnyJobCompleteInfo processJob(AnyJobConfigInfo config, SubmitInventoryUpdate submitInventory, SubmitEnrollmentRequest submitEnrollmentRequest, SubmitDiscoveryResults sdr)
        {
            Logger.Debug($"Begin Management...");

            bool hasPassword = !string.IsNullOrEmpty(config.Job.PfxPassword);
            byte[] certBytes = Convert.FromBase64String(config.Job.EntryContents);
            
            dynamic properties = JsonConvert.DeserializeObject(config.Store.Properties.ToString());
            bool hasSeparatePrivateKey = properties.separatePrivateKey == null || string.IsNullOrEmpty(properties.separatePrivateKey.Value) ? false : Boolean.Parse(properties.separatePrivateKey.Value);
            string privateKeyPath = hasSeparatePrivateKey ? (properties.pathToPrivateKey == null || string.IsNullOrEmpty(properties.pathToPrivateKey.Value) ? null : properties.pathToPrivateKey.Value) : string.Empty;

            PEMStore pemStore = new PEMStore(config.Store.ClientMachine, config.Server.Username, config.Server.Password, config.Store.StorePath, config.Store.StorePassword, Enum.Parse(typeof(PEMStore.FormatTypeEnum), properties.type.Value, true), 
                privateKeyPath);

            try
            {
                switch (config.Job.OperationType)
                {
                    case AnyJobOperationType.Add:
                        if (!config.Job.Overwrite)
                        {
                            if (pemStore.DoesStoreExist(config.Store.StorePath))
                                throw new PEMException($"Certificate store already exists for {config.Store.StorePath}.  Check 'Overwrite' to overwrite the existing store.");
                        }

                        pemStore.AddCertificateToStore(config.Job.EntryContents, config.Job.PfxPassword, config.Store.StorePassword);

                        break;

                    case AnyJobOperationType.Remove:
                        if (!pemStore.DoesStoreExist(config.Store.StorePath))
                            throw new PEMException($"Certificate store {config.Store.StorePath} does not exist and cannot be removed.");

                        pemStore.RemoveCertificate();

                        break;

                    default:
                        return new AnyJobCompleteInfo() { Status = 4, Message = $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}: Unsupported operation: {config.Job.OperationType.ToString()}" };
                }
            }
            catch (Exception ex)
            {
                return new AnyJobCompleteInfo() { Status = 4, Message = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}:") };
            }

            return new AnyJobCompleteInfo() { Status = 2, Message = "Successful" };
        }
    }
}