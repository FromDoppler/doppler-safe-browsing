using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing
{
    /// <summary>
    /// Result of Safe Browsing verification
    /// </summary>
    public sealed class SafeBrowsingStatus
    {
        /// <summary>
        /// Type of threat
        /// </summary>
        public ThreatType ThreatType { get; }

        /// <summary>
        /// URL
        /// </summary>
        public string Url { get; }

        /// <summary>
        /// True when URL has been evaluated as safe
        /// </summary>
        public bool IsSafe => ThreatType == ThreatType.NoThreat;

        /// <summary>
        /// Create a new Safe Browsing result
        /// </summary>
        /// <param name="url"></param>
        /// <param name="threatType"></param>
        public SafeBrowsingStatus(string url, ThreatType threatType)
        {
            Url = url;
            ThreatType = threatType;
        }
    }

    /// <summary>
    /// Type of threat
    /// </summary>
    [Flags]
    public enum ThreatType
    {
        /// <summary>
        /// URL seems to be safe
        /// </summary>
        NoThreat = 0,
        /// <summary>
        /// URL is suspected of hosting malware
        /// </summary>
        Malware = 1,
        /// <summary>
        /// URL is suspected of hosting unwanted software
        /// </summary>
        Unwanted = 2,
        /// <summary>
        /// URL is suspected of phishing
        /// </summary>
        Phishing = 4,
        /// <summary>
        /// URL is suspected of an unknown threat
        /// </summary>
        Unknow = 64
    }
}
