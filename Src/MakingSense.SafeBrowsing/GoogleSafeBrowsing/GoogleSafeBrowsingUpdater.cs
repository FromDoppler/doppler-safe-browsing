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
        private readonly ISafeBrowsingService _safeBrowsingService;
        private DateTimeOffset? _lastSnapshot;

        public GoogleSafeBrowsingDatabase Database { get; }


        private const string ANY_PLATFORM = "ANY_PLATFORM";
        private const string URL = "URL";
        private const string RAW = "RAW";
        private const string FULL_UPDATE = "FULL_UPDATE";

        /// <summary>
        /// Creates new instance and initializes configuration parameters
        /// </summary>
        /// <param name="configuration">Google Safe Browsing configuration</param>
        /// <param name="safeBrowsingService">Optional ISafeBrowsingService implementation</param>
        /// <param name="database">Optional GoogleSafeBrowsingDatabase instance</param>
        public GoogleSafeBrowsingUpdater(GoogleSafeBrowsingConfiguration configuration, 
            ISafeBrowsingService safeBrowsingService = null,
            GoogleSafeBrowsingDatabase database = null)
        {
            _configuration = configuration;
            _safeBrowsingService = safeBrowsingService ?? new SafeBrowsingService(_configuration.ApiKey);
            Database = database ?? new GoogleSafeBrowsingDatabase();
        }

        /// <summary>
        /// Updates Google Safe Browsing lists based on the remote resource
        /// </summary>
        /// <returns></returns>
        public async Task UpdateAsync()
        {
            if (!Database.AllowRequest)
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
                ListUpdateRequests = Database.SuspiciousLists.Select(list => new ListUpdateRequest
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
                Database.EnterBackOffMode();
                throw;
            }

            if (Database.BackOffMode)
            {
                Database.ExitBackOffMode();
            }

            var minDuration = response.MinimumWaitDuration as string;

            var minWaitDuration = minDuration != null ? 
                TimeSpan.FromSeconds(double.Parse(minDuration.TrimEnd('s'))) as TimeSpan?
                : null;

            var listUpdates = response.ListUpdateResponses.Select(MapListUpdate);

            Database.Update(DateTimeOffset.Now, minWaitDuration, listUpdates);

            if(Database.SnapshotPath != null && (!_lastSnapshot.HasValue || DateTimeOffset.UtcNow > _lastSnapshot.Value.Add(_configuration.DatabaseSnapshotInterval) ))
            {
                Database.SaveSnapshot();
                _lastSnapshot = DateTimeOffset.UtcNow;
            }
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
                RemovalsIndices = response.Removals?.SelectMany(x => x.RawIndices.Indices).Where(x => x.HasValue).Select(x => x.Value),
                Checksum = Convert.FromBase64String(response.Checksum.Sha256)
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