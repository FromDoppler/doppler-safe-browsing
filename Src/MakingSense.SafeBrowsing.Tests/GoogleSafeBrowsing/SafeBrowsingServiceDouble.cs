#if !(NET35 || NET40 || NETSTANDARD1_0)
using MakingSense.SafeBrowsing.GoogleSafeBrowsing;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Google.Apis.Safebrowsing.v4.Data;
using Google;

namespace MakingSense.SafeBrowsing.Tests.GoogleSafeBrowsing
{
    class SafeBrowsingServiceDouble : ISafeBrowsingService
    {
        private Func<FetchThreatListUpdatesRequest, FetchThreatListUpdatesResponse> _overrideFetchThreatListUpdatesAsync = 
            (a) => new FetchThreatListUpdatesResponse();

        public void Setup_FetchThreatListUpdatesAsync(Exception exception) =>
            _overrideFetchThreatListUpdatesAsync = (request) => throw new GoogleApiException("", "", exception);

        public void Setup_FetchThreatListUpdatesAsync(FetchThreatListUpdatesResponse response) =>
            _overrideFetchThreatListUpdatesAsync = (request) => response;

        public async Task<FetchThreatListUpdatesResponse> FetchThreatListUpdatesAsync(FetchThreatListUpdatesRequest request) =>
            _overrideFetchThreatListUpdatesAsync(request);
    }
}

#endif