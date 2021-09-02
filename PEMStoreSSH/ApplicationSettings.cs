﻿using System.Configuration;
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

            UseSudo = jsonContents.UseSudo == null ? false : jsonContents.UseSudo.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            CreateStoreOnAddIfMissing = jsonContents.CreateStoreOnAddIfMissing == null ? false : jsonContents.CreateStoreOnAddIfMissing.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            UseSeparateUploadFilePath = jsonContents.UseSeparateUploadFilePath == null ? false : jsonContents.UseSeparateUploadFilePath.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            SeparateUploadFilePath = jsonContents.SeparateUploadFilePath == null ? string.Empty : AddTrailingSlash(jsonContents.SeparateUploadFilePath.Value);
            UseNegotiateAuth = jsonContents.UseNegotiateAuth == null ? false : jsonContents.UseNegotiateAuth.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
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
                throw new JKSException($"The following configuration items are missing from the config.json file: {errors.Substring(0, errors.Length - 2)}");
        }
    }
}

