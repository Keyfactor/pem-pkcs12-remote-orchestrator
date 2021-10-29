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
using System.Security.Cryptography.X509Certificates;

namespace Keyfactor.Extensions.Orchestrator.PEMStoreSSH
{
    public class Inventory: IInventoryJobExtension
    {
        public string ExtensionName => "PEM-SSH";

        public JobResult ProcessJob(InventoryJobConfiguration config, SubmitInventoryUpdate submitInventory)
        {
            ILogger logger = LogHandler.GetClassLogger<Inventory>();
            logger.LogDebug($"Begin Inventory.......");

            CertificateStore certStore = config.CertificateStoreDetails;
            List<CurrentInventoryItem> inventoryItems = new List<CurrentInventoryItem>();
            X509Certificate2Collection certificates = new X509Certificate2Collection();
            try
            {
                ApplicationSettings.Initialize(this.GetType().Assembly.Location);

                dynamic properties = JsonConvert.DeserializeObject(certStore.Properties.ToString());
                logger.LogDebug($"Properties: {properties}");
                bool hasSeparatePrivateKey = properties.separatePrivateKey == null || string.IsNullOrEmpty(properties.separatePrivateKey.Value) ? false : Boolean.Parse(properties.separatePrivateKey.Value);
                string privateKeyPath = hasSeparatePrivateKey ? (properties.pathToPrivateKey == null || string.IsNullOrEmpty(properties.pathToPrivateKey.Value) ? null : properties.pathToPrivateKey.Value) : string.Empty;
                logger.LogDebug($"Path to Key: {privateKeyPath}");
                if (properties.type == null || string.IsNullOrEmpty(properties.type.Value))
                {
                    throw new PEMException("Mising certificate store Type.  Please ensure store is defined as either PEM or PKCS12.");
                }
                if (hasSeparatePrivateKey && string.IsNullOrEmpty(privateKeyPath))
                {
                    throw new PEMException("Certificate store is set has having a separate private key but no private key path is specified in the store definition.");
                }


                PEMStore pemStore = new PEMStore
                (
                    certStore.ClientMachine,
                    config.ServerUsername,
                    config.ServerPassword,
                    certStore.StorePath,
                    certStore.StorePassword,
                    Enum.Parse(typeof(PEMStore.FormatTypeEnum), properties.type.Value),
                    privateKeyPath
                );

                bool containsPrivateKey;
                certificates = pemStore.GetCertificates(certStore.StorePassword, out containsPrivateKey);
                bool isAChain = containsPrivateKey && certificates.Count > 1;

                if (isAChain)
                {
                    List<string> certList = new List<string>();
                    foreach (X509Certificate2 certificate in certificates)
                    {
                        certList.Add(Convert.ToBase64String(certificate.Export(X509ContentType.Cert)));
                    }

                    inventoryItems.Add(new CurrentInventoryItem()
                    {
                        ItemStatus = OrchestratorInventoryItemStatus.Unknown,
                        Alias = string.IsNullOrEmpty(certificates[0].FriendlyName) ? certificates[0].Thumbprint : certificates[0].FriendlyName,
                        PrivateKeyEntry = containsPrivateKey,
                        UseChainLevel = isAChain,
                        Certificates = certList.ToArray()
                    });
                }
                else
                {
                    foreach (X509Certificate2 certificate in certificates)
                    {
                        inventoryItems.Add(new CurrentInventoryItem()
                        {
                            ItemStatus = OrchestratorInventoryItemStatus.Unknown,
                            Alias = string.IsNullOrEmpty(certificate.FriendlyName) ? certificate.Thumbprint : certificate.FriendlyName,
                            PrivateKeyEntry = containsPrivateKey,
                            UseChainLevel = isAChain,
                            Certificates = new string[] { Convert.ToBase64String(certificate.Export(X509ContentType.Cert)) }
                        });
                    }
                }

            }
            catch (Exception ex)
            {
                return new JobResult()
                {
                    JobHistoryId = config.JobHistoryId,
                    Result = OrchestratorJobStatusJobResult.Failure,
                    FailureMessage = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {certStore.StorePath} on server {certStore.ClientMachine}:")
                };
            }

            try
            {
                submitInventory.Invoke(inventoryItems);
                return new JobResult()
                {
                    JobHistoryId = config.JobHistoryId,
                    Result = certificates.Count == 0 ? OrchestratorJobStatusJobResult.Warning : OrchestratorJobStatusJobResult.Success,
                };
            }
            catch (Exception ex)
            {
                return new JobResult()
                {
                    JobHistoryId = config.JobHistoryId,
                    Result = OrchestratorJobStatusJobResult.Failure,
                    FailureMessage = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {certStore.StorePath} on server {certStore.ClientMachine}:")
                };
            }
        }
    }
}