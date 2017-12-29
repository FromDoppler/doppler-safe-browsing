using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.GoogleSafeBrowsing
{
    /// <summary>
    /// In-memory database to store Google Safe Browsing lists
    /// </summary>
    public class GoogleSafeBrowsingDatabase
    {
        private const string SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING";
        private const string UNWANTED_SOFTWARE = "UNWANTED_SOFTWARE";
        private const string MALWARE = "MALWARE";

        /// <summary>
        /// The minimum duration the client must wait before issuing any update request. 
        /// If this field is not set clients may update as soon as they want.
        /// </summary>
        public TimeSpan? MinimumWaitDuration { get; set; } = null;

        /// <summary>
        /// Last time Google Safe Browsing lists were updated
        /// </summary>
        public DateTimeOffset? Updated { get; set; } = null;

        /// <summary>
        /// Google Safe Browsing lists
        /// </summary>
        public Dictionary<string, SafeBrowsingList> SuspiciousLists { get; set; }

        /// <summary>
        /// Returns true if MinimumWaitDuration has passed since last update or if it is the initial download
        /// </summary>
        public bool AllowRequest
        {
            get
            {
                return !(Updated.HasValue && MinimumWaitDuration.HasValue && Updated.Value.Add(MinimumWaitDuration.Value) >= DateTimeOffset.Now);
            }
        }

        /// <summary>
        /// Initialize an instance with default SuspiciousLists
        /// </summary>
        public GoogleSafeBrowsingDatabase()
        {
            SuspiciousLists = new Dictionary<string, SafeBrowsingList> {
                [SOCIAL_ENGINEERING] = new SafeBrowsingList(),
                [UNWANTED_SOFTWARE] = new SafeBrowsingList(),
                [MALWARE] = new SafeBrowsingList(),
            };
        }
    }

    /// <summary>
    /// Google Safe Browsing list
    /// </summary>
    public class SafeBrowsingList
    {
        /// <summary>
        /// Url hash prefix list. Hashes can be anywhere from 4 to 32 bytes in size.
        /// </summary>
        public List<byte[]> Hashes { get; set; } = new List<byte[]>();

        /// <summary>
        /// The current state of the client for the requested list 
        /// (the encrypted client state that was received from the last successful list update).
        /// </summary>
        public string State { get; set; } = string.Empty;
    }
}
