using System;
using System.Collections.Generic;
using System.Linq;

using Newtonsoft.Json;

using Keyfactor.Platform.Extensions.Agents;
using Keyfactor.Platform.Extensions.Agents.Delegates;
using Keyfactor.Platform.Extensions.Agents.Interfaces;

using CSS.Common.Logging;

namespace PEMStoreSSH
{
    public class Discovery : LoggingClientBase, IAgentJobExtension
    {
        public string GetJobClass()
        {
            return "Discovery";
        }

        public string GetStoreType()
        {
            return "PEM-SSH";
        }
            
        public AnyJobCompleteInfo processJob(AnyJobConfigInfo config, SubmitInventoryUpdate submitInventory, SubmitEnrollmentRequest submitEnrollmentRequest, SubmitDiscoveryResults sdr)
        {
            Logger.Debug($"Begin Discovery...");

            List<string> locations = new List<string>();
            string server = string.Empty;

            try
            {
                dynamic properties = JsonConvert.DeserializeObject(config.Job.Properties.ToString());
                string[] directoriesToSearch = properties.dirs.Value.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                string[] extensionsToSearch = properties.extensions.Value.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                string[] ignoredDirs = properties.ignoreddirs.Value.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                PEMStore pemStore = new PEMStore(config.Store.ClientMachine, config.Server.Username, config.Server.Password, directoriesToSearch[0].Substring(0, 1) == "/" ? PEMStore.ServerTypeEnum.Linux : PEMStore.ServerTypeEnum.Windows);

                locations = pemStore.FindStores(directoriesToSearch, extensionsToSearch).ToList();
                foreach (string ignoredDir in ignoredDirs)
                    locations = locations.Where(p => !p.StartsWith(ignoredDir.TrimStart(' '))).ToList();

                // commented out because IsValidCertificate depends on the text inside a CryptographicException
                //locations = locations.Where(p => pemStore.IsValidCertificate(p)).Select(p => server + ":" + p).ToList();
            }
            catch (Exception ex)
            {
                return new AnyJobCompleteInfo() { Status = 4, Message = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}:") };
            }

            try
            {
                sdr.Invoke(locations);
                return new AnyJobCompleteInfo() { Status = 2, Message = "Successful" };
            }
            catch (Exception ex)
            {
                return new AnyJobCompleteInfo() { Status = 4, Message = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}:") };
            }
        }
    }
}