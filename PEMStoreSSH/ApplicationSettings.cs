using System.Configuration;
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

            UseSudo = jsonContents.UseSudo == null ? false : jsonContents.UseSudo.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            CreateStoreOnAddIfMissing = jsonContents.CreateStoreOnAddIfMissing == null ? false : jsonContents.CreateStoreOnAddIfMissing.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            UseSeparateUploadFilePath = jsonContents.UseSeparateUploadFilePath == null ? string.Empty : jsonContents.UseSeparateUploadFilePath.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            SeparateUploadFilePath = jsonContents.SeparateUploadFilePath == null ? string.Empty : AddTrailingSlash(jsonContents.SeparateUploadFilePath.Value);
            UseNegotiateAuth = jsonContents.UseNegotiateAuth == null ? false : jsonContents.UseNegotiateAuth.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
        }

        private static string AddTrailingSlash(string path)
        {
            if (path.Length == 0)
                return string.Empty;
            return path.Substring(path.Length - 1, 1) == @"/" ? path : path += @"/";
        }
    }
}

