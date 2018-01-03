#if !(NET35 || NET40 || NETSTANDARD1_0)
using Google.Apis.Safebrowsing.v4.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.GoogleSafeBrowsing
{
    /// <summary>
    /// Allow to download Google Safe Browsing lists from HTTP and update them
    /// </summary>
    public class GoogleSafeBrowsingUpdater : IUpdater
    {
        private readonly GoogleSafeBrowsingConfiguration _configuration;
        private readonly GoogleSafeBrowsingDatabase _database;
        private readonly ISafeBrowsingService _safeBrowsingService;

        private const string ANY_PLATFORM = "ANY_PLATFORM";
        private const string URL = "URL";
        private const string RAW = "RAW";
        private const string FULL_UPDATE = "FULL_UPDATE";

        /// <summary>
        /// Creates new instance and initializes configuration parameters
        /// </summary>
        /// <param name="configuration">Google Safe Browsing configuration</param>
        /// <param name="safeBrowsingService">Optional ISafeBrowsingService implementation</param>
        public GoogleSafeBrowsingUpdater(GoogleSafeBrowsingConfiguration configuration, ISafeBrowsingService safeBrowsingService = null)
        {
            _configuration = configuration;

            _safeBrowsingService = safeBrowsingService ?? new SafeBrowsingService(_configuration.ApiKey);

            _database = new GoogleSafeBrowsingDatabase();
        }

        /// <summary>
        /// Updates Google Safe Browsing lists based on the remote resource
        /// </summary>
        /// <returns></returns>
        public async Task UpdateAsync()
        {
            if (!_database.AllowRequest)
            {
                return;
            }

            var request = new FetchThreatListUpdatesRequest
            {
                Client = new ClientInfo
                {
                    ClientId = _configuration.ClientId,
                    ClientVersion = _configuration.ClientVersion
                },
                ListUpdateRequests = _database.SuspiciousLists.Select(list => new ListUpdateRequest
                {
                    PlatformType = ANY_PLATFORM,
                    ThreatType = list.Key.ToString(),
                    ThreatEntryType = URL,
                    State = list.Value.State,
                    Constraints = new Constraints
                    {
                        Region = _configuration.Region,
                        SupportedCompressions = new List<string> { RAW }
                    }
                }).ToList()
            };

            FetchThreatListUpdatesResponse response = null;

            try
            {
                response = await _safeBrowsingService.FetchThreatListUpdatesAsync(request);
            }
            catch (Google.GoogleApiException ex)
            {
                _database.EnterBackOffMode();
                throw;
            }

            if (_database.BackOffMode)
            {
                _database.ExitBackOffMode();
            }

            var minWaitDuration = TimeSpan.FromSeconds(double.Parse((response.MinimumWaitDuration as string).TrimEnd('s')));
            var listUpdates = response.ListUpdateResponses.Select(x=> MapListUpdate(x));

            _database.Update(DateTimeOffset.Now, minWaitDuration, listUpdates);
        }

        private ListUpdate MapListUpdate(ListUpdateResponse response)
        {
            return new ListUpdate()
            {
                ThreatType = (ThreatType) Enum.Parse(typeof(ThreatType),response.ThreatType),
                State = response.NewClientState,
                FullUpdate = response.ResponseType == FULL_UPDATE,
                AddingHashes = response.Additions?.Select(a => a.RawHashes)
                                    .SelectMany(rh => SplitByteList(Convert.FromBase64String(rh.RawHashesValue), rh.PrefixSize.Value)),
                RemovalsIndices = response.Removals?.SelectMany(x => x.RawIndices.Indices).Where(x => x.HasValue).Select(x => x.Value)
            };
        }

        /// <summary>
        /// Split an array of bytes in smaller arrays based on input size.
        /// </summary>
        /// <param name="bytes">Original long array of bytes</param>
        /// <param name="size">New small arrays lenth</param>
        /// <returns>List of splitted arrays of bytes</returns>
        private List<byte[]> SplitByteList(byte[] bytes, int size)
        {
            var list = new List<byte[]>();

            for (int i = 0; i < bytes.Length; i = i + size)
            {
                var aux = new byte[size];
                Array.Copy(bytes, i, aux, 0, size);
                list.Add(aux);
            }

            return list;
        }
    }
}
#endif