#if !(NET35 || NET40 || NETSTANDARD1_0)
using Google.Apis.Safebrowsing.v4;
using Google.Apis.Safebrowsing.v4.Data;
using Google.Apis.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.GoogleSafeBrowsing
{
    public class SafeBrowsingService : ISafeBrowsingService
    {
        private readonly SafebrowsingService _safebrowsingService;

        public async Task<FetchThreatListUpdatesResponse> FetchThreatListUpdatesAsync(FetchThreatListUpdatesRequest request)
        {
            return await _safebrowsingService.ThreatListUpdates.Fetch(request).ExecuteAsync();
        }

        public SafeBrowsingService(string apiKey)
        {
            _safebrowsingService = new SafebrowsingService(new BaseClientService.Initializer
            {
                ApiKey = apiKey,
            });
        }
    }
}
#endif
