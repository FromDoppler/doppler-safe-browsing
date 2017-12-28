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
    public class GoogleSafeBrowsingUpdater : IUpdater
    {
        private readonly GoogleSafeBrowsingConfiguration _configuration;
        private readonly GoogleSafeBrowsingDatabase _database;
        private readonly SafebrowsingService _safebrowsingService;

        private const string ANY_PLATFORM = "ANY_PLATFORM";
        private const string URL = "URL";
        private const string RAW = "RAW";
        private const string FULL_UPDATE = "FULL_UPDATE";

        public GoogleSafeBrowsingUpdater(string apiKey, string clientId, string clientVersion, string region)
        {
            _configuration = new GoogleSafeBrowsingConfiguration
            {
                ApiKey = apiKey,
                ClientId = clientId,
                ClientVersion = clientVersion,
                Region = region
            };

            _safebrowsingService = new SafebrowsingService(new BaseClientService.Initializer
            {
                ApiKey = _configuration.ApiKey,
            });

            _database = new GoogleSafeBrowsingDatabase();
        }

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
                ListUpdateRequests = _database.UnsafeLists.Select(list => new ListUpdateRequest
                {
                    PlatformType = ANY_PLATFORM,
                    ThreatType = list.Key,
                    ThreatEntryType = URL,
                    State = list.Value.State,
                    Constraints = new Constraints
                    {
                        Region = _configuration.Region,
                        SupportedCompressions = new List<string>
                    {
                        RAW
                    }
                    }
                }).ToList()
            };

            var response = await _safebrowsingService.ThreatListUpdates.Fetch(request).ExecuteAsync();

            _database.MinimumWaitDuration = TimeSpan.FromSeconds(double.Parse((response.MinimumWaitDuration as string).TrimEnd('s')));
            _database.Updated = DateTimeOffset.Now;

            foreach (var listUpdate in response.ListUpdateResponses)
            {
                if(listUpdate.ResponseType == FULL_UPDATE)
                {
                    _database.UnsafeLists[listUpdate.ThreatType] = new UnsafeList
                    {
                        State = response.ListUpdateResponses.First().NewClientState
                    };

                    foreach (var add in listUpdate.Additions)
                    {
                        var rawHashes = add.RawHashes;
                        var hashValues = Convert.FromBase64String(rawHashes.RawHashesValue);
                        _database.UnsafeLists[listUpdate.ThreatType].Hashes.AddRange(SplitByteList(hashValues, rawHashes.PrefixSize.Value));
                    }

                    //_database.UnsafeLists[listUpdate.ThreatType].Hashes.Sort();
                }
                else
                {
                    //TODO: implement partial updates
                }
            }
        }

        private List<byte[]> SplitByteList(byte[] bytes, int size)
        {
            var list = new List<byte[]>();
            var aux = new List<byte>();

            for (int i = 0; i < bytes.Length; i++)
            {
                aux.Add(bytes[i]);

                if (aux.Count == size)
                {
                    list.Add(aux.ToArray());
                    aux = new List<byte>();
                }
            }

            return list;
        }
    }
}
#endif