// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;

using Keyfactor.Platform.Extensions.Agents;

namespace PEMStoreSSH
{
    public partial class Management
    {
        private class PEMRequest
        {

            private string _pfxPassword = string.Empty;
            public bool IsPfxFile { get; }
            public X509Certificate2 Certificate { get; }
            public string StorePath { get; }
            public string StorePassword { get; }
            public string KeyPath { get; }
            public bool HasSeparatePrivateKey { get; }
            
            public PEMRequest(AnyJobConfigInfo config)
            {

                StorePath = config.Store.StorePath;
                StorePassword = config.Store.StorePassword;
                _pfxPassword = config.Job.PfxPassword;

                IsPfxFile = !string.IsNullOrEmpty(config.Job.PfxPassword);

                if (IsPfxFile)
                {
                    Certificate = new X509Certificate2(Convert.FromBase64String(config.Job.EntryContents), _pfxPassword, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                }
                else
                {
                    Certificate = new X509Certificate2(Convert.FromBase64String(config.Job.EntryContents));
                }

                dynamic properties = JsonConvert.DeserializeObject(config.Store.Properties.ToString());
                HasSeparatePrivateKey = properties.separatePrivateKey == null || string.IsNullOrEmpty(properties.separatePrivateKey.Value) ? false : bool.Parse(properties.separatePrivateKey.Value);
                KeyPath = HasSeparatePrivateKey ? (properties.pathToPrivateKey == null || string.IsNullOrEmpty(properties.pathToPrivateKey.Value) ? null : properties.pathToPrivateKey.Value) : string.Empty;

            }   
        }
    }
}