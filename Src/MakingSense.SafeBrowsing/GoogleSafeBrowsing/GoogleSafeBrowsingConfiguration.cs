using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.GoogleSafeBrowsing
{
    public class GoogleSafeBrowsingConfiguration
    {
        public string ApiKey { get; set; }

        public string ClientId { get; set; }

        public string ClientVersion { get; set; }

        public string Region { get; set; }
    }
}
