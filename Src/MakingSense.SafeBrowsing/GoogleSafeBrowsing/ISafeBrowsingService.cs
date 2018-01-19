#if !(NET35 || NET40 || NETSTANDARD1_0)
using Google.Apis.Safebrowsing.v4.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.GoogleSafeBrowsing
{
    public interface ISafeBrowsingService
    {
        Task<FetchThreatListUpdatesResponse> FetchThreatListUpdatesAsync(FetchThreatListUpdatesRequest request);
    }
}
#endif
