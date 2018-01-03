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
    /// <summary>
    /// Allow to download Google Safe Browsing lists from HTTP and update them
    /// </summary>
    public class GoogleSafeBrowsingUpdater : IUpdater
    {
        private readonly GoogleSafeBrowsingConfiguration _configuration;
        private readonly GoogleSafeBrowsingDatabase _database;
        private readonly SafebrowsingService _safebrowsingService;

        private const string ANY_PLATFORM = "ANY_PLATFORM";
        private const string URL = "URL";
        private const string RAW = "RAW";
        private const string FULL_UPDATE = "FULL_UPDATE";

        /// <summary>
        /// Creates new instance and initializes configuration parameters
        /// </summary>
        /// <param name="configuration">Google Safe Browsing configuration</param>
        public GoogleSafeBrowsingUpdater(GoogleSafeBrowsingConfiguration configuration)
        {
            _configuration = configuration;

            _safebrowsingService = new SafebrowsingService(new BaseClientService.Initializer
            {
                ApiKey = _configuration.ApiKey,
            });

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
                    ThreatType = list.Key,
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
                response = await _safebrowsingService.ThreatListUpdates.Fetch(request).ExecuteAsync();
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

            _database.MinimumWaitDuration = TimeSpan.FromSeconds(double.Parse((response.MinimumWaitDuration as string).TrimEnd('s')));
            _database.Updated = DateTimeOffset.Now;

            foreach (var listUpdate in response.ListUpdateResponses)
            {
                if(_database.SuspiciousLists[listUpdate.ThreatType].State == listUpdate.NewClientState)
                {
                    continue;
                }

                IEnumerable<byte[]> hashes = _database.SuspiciousLists[listUpdate.ThreatType].Hashes;

                var newHashes = listUpdate.Additions != null ? 
                                listUpdate.Additions.Select(x => x.RawHashes)
                                    .SelectMany(rh => SplitByteList(Convert.FromBase64String(rh.RawHashesValue), rh.PrefixSize.Value)) : 
                                new List<byte[]>();

                if (listUpdate.ResponseType == FULL_UPDATE)
                {
                    hashes = newHashes;
                }
                else
                {
                    if(listUpdate.Removals != null)
                    {
                        var indices = listUpdate.Removals.SelectMany(x => x.RawIndices.Indices);

                        hashes = hashes.Where((x, index) => !indices.Contains(index));
                    }

                    hashes = hashes.Concat(newHashes);
                }

                _database.SuspiciousLists[listUpdate.ThreatType].State = listUpdate.NewClientState;
                _database.SuspiciousLists[listUpdate.ThreatType].Hashes = OrderList(hashes);

                //TODO: verify checksum - if not valid, state should be empty to try full update the next time
                // if checksum not match
                //      _database.SuspiciousLists[listUpdate.ThreatType].State = null;
            }
        }


        private List<byte[]> OrderList(IEnumerable<byte[]> list)
        {
            var orderedList = new List<byte[]>();

            foreach (var item in list.OrderBy(x => x, new ByteArrayComparer()))
            {
                // Creating the list manually as ToList get stuck
                orderedList.Add(item);
            }

            return orderedList;
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


        public class ByteArrayComparer : IComparer<byte[]>
        {
            public int Compare(byte[] x, byte[] y)
            {
                int result;
                var min = Math.Min(x.Length, y.Length);
                for (int index = 0; index < min; index++)
                {
                    result = x[index].CompareTo(y[index]);
                    if (result != 0) return result;
                }
                return x.Length.CompareTo(y.Length);
            }
        }

    }
}
#endif