using System.Configuration;
using System.IO;

using Newtonsoft.Json;

namespace PEMStoreSSH
{
    class ApplicationSettings
    {
        public static bool UseSudo { get; set; }
        public static bool CreateStoreOnAddIfMissing { get; set; }

        public static void Initialize(string currLocation)
        {
            string configContents = string.Empty;
            string currDir = Path.GetDirectoryName(currLocation);

            using (StreamReader sr = new StreamReader($@"{currDir}\config.json"))
            {
                configContents = sr.ReadToEnd();
            }

            dynamic jsonContents = JsonConvert.DeserializeObject(configContents);

            UseSudo = jsonContents.UseSudo.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            CreateStoreOnAddIfMissing = jsonContents.CreateStoreOnAddIfMissing.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
        }
    }
}

