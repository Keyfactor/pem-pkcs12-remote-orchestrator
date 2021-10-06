// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.IO;

using Newtonsoft.Json;

namespace PEMStoreSSH
{
    class ApplicationSettings
    {
        public static bool UseSudo { get; set; }
        public static bool CreateStoreOnAddIfMissing { get; set; }
        public static bool UseSeparateUploadFilePath { get; set; }
        public static string SeparateUploadFilePath { get; set; }
        public static bool UseNegotiateAuth { get; set; }

        public static void Initialize(string currLocation)
        {
            string configContents = string.Empty;
            string currDir = Path.GetDirectoryName(currLocation);

            using (StreamReader sr = new StreamReader($@"{currDir}\config.json"))
            {
                configContents = sr.ReadToEnd();
            }

            dynamic jsonContents = JsonConvert.DeserializeObject(configContents);

            ValidateConfig(jsonContents);

            UseSudo = jsonContents.UseSudo.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            CreateStoreOnAddIfMissing = jsonContents.CreateStoreOnAddIfMissing.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            UseSeparateUploadFilePath = jsonContents.UseSeparateUploadFilePath.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            SeparateUploadFilePath = AddTrailingSlash(jsonContents.SeparateUploadFilePath.Value);
            UseNegotiateAuth = jsonContents.UseNegotiateAuth.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
        }

        private static string AddTrailingSlash(string path)
        {
            if (path.Length == 0)
                return string.Empty;
            return path.Substring(path.Length - 1, 1) == @"/" ? path : path += @"/";
        }

        private static void ValidateConfig(dynamic jsonContents)
        {
            string errors = string.Empty;

            if (jsonContents.UseSudo == null)
                errors += "UseSudo, ";
            if (jsonContents.CreateStoreOnAddIfMissing == null)
                errors += "CreateStoreOnAddIfMissing, ";
            if (jsonContents.UseSeparateUploadFilePath == null)
                errors += "UseSeparateUploadFilePath, ";
            if (jsonContents.SeparateUploadFilePath == null)
                errors += "SeparateUploadFilePath, ";
            if (jsonContents.UseNegotiateAuth == null)
                errors += "UseNegotiateAuth, ";

            if (errors.Length > 0)
                throw new PEMException($"The following configuration items are missing from the config.json file: {errors.Substring(0, errors.Length - 2)}");
        }
    }
}

