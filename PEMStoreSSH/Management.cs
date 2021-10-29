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

namespace Keyfactor.Extensions.Orchestrator.PEMStoreSSH
{
    public partial class Management: IManagementJobExtension
    {
        public string ExtensionName => "PEM-SSH";

        public JobResult ProcessJob(ManagementJobConfiguration config)
        {
            ILogger logger = LogHandler.GetClassLogger<Management>();
            logger.LogDebug($"Begin Management...");

            CertificateStore certStore = config.CertificateStoreDetails;
            ManagementJobCertificate jobCert = config.JobCertificate;
            bool hasPassword = !string.IsNullOrEmpty(jobCert.PrivateKeyPassword);
            
            dynamic properties = JsonConvert.DeserializeObject(certStore.Properties.ToString());
            bool hasSeparatePrivateKey = properties.separatePrivateKey == null || string.IsNullOrEmpty(properties.separatePrivateKey.Value) ? false : bool.Parse(properties.separatePrivateKey.Value);
            string privateKeyPath = hasSeparatePrivateKey ? (properties.pathToPrivateKey == null || string.IsNullOrEmpty(properties.pathToPrivateKey.Value) ? null : properties.pathToPrivateKey.Value) : string.Empty;

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
                Enum.Parse(typeof(PEMStore.FormatTypeEnum), properties.type.Value, true), 
                privateKeyPath
            );

            if (properties.isSingleCertificateStore != null && !string.IsNullOrEmpty(properties.isSingleCertificateStore.Value))
            {
                pemStore.IsSingleCertificateStore = bool.Parse(properties.isSingleCertificateStore.Value);
            }

            try
            {
                ApplicationSettings.Initialize(this.GetType().Assembly.Location);

                switch (config.OperationType)
                {
                    case CertStoreOperationType.Add:
                        bool storeExists = pemStore.DoesStoreExist(certStore.StorePath);

                        if (ApplicationSettings.CreateStoreOnAddIfMissing && !storeExists)
                        {
                            pemStore.CreateEmptyStoreFile(certStore.StorePath);
                            if (hasSeparatePrivateKey && privateKeyPath != null)
                                pemStore.CreateEmptyStoreFile(privateKeyPath);
                        }

                        if (!ApplicationSettings.CreateStoreOnAddIfMissing && !storeExists)
                        {
                            throw new PEMException($"Certificate store {certStore.StorePath} does not exist.");
                        }

                        pemStore.AddCertificateToStore
                        (
                            jobCert.Contents,
                            jobCert.Alias,
                            jobCert.PrivateKeyPassword,
                            certStore.StorePassword,
                            config.Overwrite,
                            hasPassword
                        );

                        break;

                    case CertStoreOperationType.Remove:
                        if (!pemStore.DoesStoreExist(certStore.StorePath))
                        {
                            throw new PEMException($"Certificate store {certStore.StorePath} does not exist.");
                        }

                        pemStore.RemoveCertificate(jobCert.Alias);

                        break;

                    case CertStoreOperationType.Create:
                        if (pemStore.DoesStoreExist(certStore.StorePath))
                        {
                            throw new PEMException($"Certificate store {certStore.StorePath} already exists and cannot be created.");
                        }

                        pemStore.CreateEmptyStoreFile(certStore.StorePath);
                        if (hasSeparatePrivateKey && privateKeyPath != null)
                        {
                            pemStore.CreateEmptyStoreFile(privateKeyPath);
                        }

                        break;

                    default:
                        return new JobResult()
                        {
                            JobHistoryId = config.JobHistoryId,
                            Result = OrchestratorJobStatusJobResult.Failure,
                            FailureMessage = $"Site {certStore.StorePath} on server {certStore.ClientMachine}: Unsupported operation: {config.OperationType}"
                        };
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

            return new JobResult()
            {
                JobHistoryId = config.JobHistoryId,
                Result = OrchestratorJobStatusJobResult.Success
            };
        }
    }
} 