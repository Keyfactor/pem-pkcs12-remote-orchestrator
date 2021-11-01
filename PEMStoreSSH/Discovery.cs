// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.Logging;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Orchestrators.Extensions;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Keyfactor.Extensions.Orchestrator.PEMStoreSSH
{
    public class Discovery : IDiscoveryJobExtension
    {
        public string ExtensionName => "PEM-SSH";
            
        public JobResult ProcessJob(DiscoveryJobConfiguration config, SubmitDiscoveryUpdate submitDiscovery)
        {
            ILogger logger = LogHandler.GetClassLogger<Discovery>();
            logger.LogDebug($"Begin Discovery...");

            List<string> locations = new List<string>();

            try
            {
                ApplicationSettings.Initialize(this.GetType().Assembly.Location);

                dynamic properties = JsonConvert.DeserializeObject(config.JobProperties.ToString());
                string[] directoriesToSearch = properties.dirs.Value.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                string[] extensionsToSearch = properties.extensions.Value.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                string[] ignoredDirs = properties.ignoreddirs.Value.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                string[] filesTosearch = properties.patterns.Value.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                bool isP12 = (bool)properties.compatibility.Value;

                if (directoriesToSearch.Length == 0)
                {
                    throw new PEMException("Blank or missing search directories for Discovery.");
                }
                else if (extensionsToSearch.Length == 0)
                {
                    throw new PEMException("Blank or missing search extensions for Discovery.");
                }

                if (filesTosearch.Length == 0)
                {
                    filesTosearch = new string[] { "*" };
                }

                PEMStore pemStore = new PEMStore
                (
                    config.ClientMachine,
                    config.ServerUsername,
                    config.ServerPassword,
                    directoriesToSearch[0].Substring(0, 1) == "/" ? PEMStore.ServerTypeEnum.Linux : PEMStore.ServerTypeEnum.Windows,
                    isP12 ? PEMStore.FormatTypeEnum.PKCS12 : PEMStore.FormatTypeEnum.PEM
                );

                locations = pemStore.FindStores(directoriesToSearch, extensionsToSearch, filesTosearch).ToList();
                foreach (string ignoredDir in ignoredDirs)
                {
                    locations = locations.Where(p => !p.StartsWith(ignoredDir.TrimStart(' '))).ToList();
                }

                locations = locations.Where(p => pemStore.IsValidStore(p)).ToList();
            }
            catch (Exception ex)
            {
                return new JobResult()
                {
                    JobHistoryId = config.JobHistoryId,
                    Result = OrchestratorJobStatusJobResult.Failure,
                    FailureMessage = ExceptionHandler.FlattenExceptionMessages(ex, $"Error on server {config.ClientMachine}:")
                };
            }

            try
            {
                submitDiscovery.Invoke(locations);
                return new JobResult()
                {
                    JobHistoryId = config.JobHistoryId,
                    Result = OrchestratorJobStatusJobResult.Success
                };
            }
            catch (Exception ex)
            {
                return new JobResult()
                {
                    JobHistoryId = config.JobHistoryId,
                    Result = OrchestratorJobStatusJobResult.Failure,
                    FailureMessage = ExceptionHandler.FlattenExceptionMessages(ex, $"Error on server {config.ClientMachine}:")
                };
            }
        }
    }
}