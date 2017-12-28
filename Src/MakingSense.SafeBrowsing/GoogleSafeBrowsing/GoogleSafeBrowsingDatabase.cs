using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.GoogleSafeBrowsing
{
    public class GoogleSafeBrowsingDatabase
    {
        private const string SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING";
        private const string UNWANTED_SOFTWARE = "UNWANTED_SOFTWARE";
        private const string MALWARE = "MALWARE";

        public TimeSpan? MinimumWaitDuration { get; set; } = null;

        public DateTimeOffset? Updated { get; set; } = null;

        public Dictionary<string, UnsafeList> UnsafeLists { get; set; }

        public bool AllowRequest
        {
            get
            {
                return !(Updated.HasValue && MinimumWaitDuration.HasValue && Updated.Value.Add(MinimumWaitDuration.Value) >= DateTimeOffset.Now);
            }
        }

        public GoogleSafeBrowsingDatabase()
        {
            UnsafeLists = new Dictionary<string, UnsafeList> {
                [SOCIAL_ENGINEERING] = new UnsafeList(),
                [UNWANTED_SOFTWARE] = new UnsafeList(),
                [MALWARE] = new UnsafeList(),
            };
        }
    }

    public class UnsafeList
    {
        public List<byte[]> Hashes { get; set; } = new List<byte[]>();

        public string State { get; set; } = string.Empty;
    }
}
