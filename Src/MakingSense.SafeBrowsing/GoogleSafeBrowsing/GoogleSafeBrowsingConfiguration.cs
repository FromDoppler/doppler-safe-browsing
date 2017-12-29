using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.GoogleSafeBrowsing
{
    /// <summary>
    /// Configuration parameters needed to interact with Google Safe Browsing API
    /// </summary>
    public class GoogleSafeBrowsingConfiguration
    {
        /// <summary>
        /// Google API KEY
        /// </summary>
        public string ApiKey { get; set; }

        /// <summary>
        /// A client ID that (hopefully) uniquely identifies the client implementation of the Safe Browsing API.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// The version of the client implementation.
        /// </summary>
        public string ClientVersion { get; set; }

        /// <summary>
        /// Requests the list for a specific geographic location. If not set the server 
        /// may pick that value based on the user's IP address. Expects ISO 3166-1 alpha-2 format.
        /// </summary>
        public string Region { get; set; }
    }
}
