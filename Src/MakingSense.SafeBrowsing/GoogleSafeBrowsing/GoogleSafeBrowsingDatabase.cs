using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MakingSense.SafeBrowsing.Internal;

namespace MakingSense.SafeBrowsing.GoogleSafeBrowsing
{
    /// <summary>
    /// In-memory database to store Google Safe Browsing lists
    /// </summary>
    public class GoogleSafeBrowsingDatabase
    {
        /// <summary>
        /// The minimum duration the client must wait before issuing any update request. 
        /// If this field is not set clients may update as soon as they want.
        /// </summary>
        public TimeSpan? MinimumWaitDuration { get; private set; } = null;

        /// <summary>
        /// Last time Google Safe Browsing lists were updated
        /// </summary>
        public DateTimeOffset? Updated { get; private set; } = null;

        /// <summary>
        /// Google Safe Browsing lists
        /// </summary>
#if !(NET35 || NET40)
        public ReadOnlyDictionary<ThreatType, SafeBrowsingList> SuspiciousLists { get; private set; }
#else
        public Dictionary<ThreatType, SafeBrowsingList> SuspiciousLists { get; private set; }
#endif

        /// <summary>
        /// Indicate if client is in back-off mode.
        /// <para>Clients that receive an unsuccessful HTTP response 
        /// (that is, any HTTP status code other than 200 OK) must enter back-off mode.
        /// Once in back-off mode, clients must wait the computed time duration before 
        /// they can issue another request to the server.</para>
        /// </summary>
        public bool BackOffMode { get; private set; } = false;

        /// <summary>
        /// Number of consecutive, unsuccessful requests that the client experiences 
        /// (starting with N=1 after the first unsuccessful request)
        /// </summary>
        public int BackOffRetryNumber { get; private set; }

        /// <summary>
        /// Random number between 0 and 1 that needs to be picked after every unsuccessful update.
        /// </summary>
        public double BackOffSeed { get; private set; }

        /// <summary>
        /// Back-off computed time duration before client can issue another request to the server. 
        /// It uses the following formula: MIN((2^(N-1) * 15 minutes) * (RAND + 1), 24 hours)
        /// </summary>
        public TimeSpan? BackOffDuration
        {
            get
            {
                return TimeSpan.FromMinutes(Math.Min(( Math.Pow(2, (BackOffRetryNumber - 1)) * 15) * (BackOffSeed + 1), 24 * 60));
            }
        }

        /// <summary>
        /// Returns true if MinimumWaitDuration has passed since last update or if it is the initial download
        /// </summary>
        public bool AllowRequest
        {
            get
            {
                if (BackOffMode)
                {
                    return !(Updated.HasValue && BackOffDuration.HasValue && Updated.Value.Add(BackOffDuration.Value) >= DateTimeOffset.Now);
                }

                return !(Updated.HasValue && MinimumWaitDuration.HasValue && Updated.Value.Add(MinimumWaitDuration.Value) >= DateTimeOffset.Now);
            }
        }

        /// <summary>
        /// Initialize an instance with default SuspiciousLists
        /// </summary>
        public GoogleSafeBrowsingDatabase()
        {
            var dictionary = new Dictionary<ThreatType, SafeBrowsingList>
            {
                [ThreatType.SOCIAL_ENGINEERING] = new SafeBrowsingList(),
                [ThreatType.UNWANTED_SOFTWARE] = new SafeBrowsingList(),
                [ThreatType.MALWARE] = new SafeBrowsingList(),
            };

#if !(NET35 || NET40)
            SuspiciousLists = new ReadOnlyDictionary<ThreatType, SafeBrowsingList>(dictionary);
#else
            SuspiciousLists = dictionary;
#endif
        }

        /// <summary>
        /// Enter back-off mode after receive an unsuccessful HTTP response.
        /// </summary>
        public void EnterBackOffMode()
        {
            Random random = new Random();
            BackOffSeed = random.NextDouble();
            Updated = DateTimeOffset.Now;

            if (!BackOffMode)
            {
                BackOffMode = true;
                BackOffRetryNumber = 1;
            }
            else
            {
                BackOffRetryNumber++;
            }
        }

        /// <summary>
        /// Exit back-off mode after receive a successful HTTP response.
        /// </summary>
        public void ExitBackOffMode()
        {
            BackOffMode = false;
        }

        /// <summary>
        /// Update SuspiciousLists
        /// </summary>
        /// <param name="now">Now</param>
        /// <param name="minWaitDuration">Minimum wait duration</param>
        /// <param name="listUpdates">Collection of ListUpdate</param>
        public void Update(DateTimeOffset now, TimeSpan? minWaitDuration, IEnumerable<ListUpdate> listUpdates)
        {
            MinimumWaitDuration = minWaitDuration;

            foreach (var listUpdate in listUpdates)
            {
                if (SuspiciousLists[listUpdate.ThreatType].State == listUpdate.State)
                {
                    continue;
                }

                var hashes = SuspiciousLists[listUpdate.ThreatType].Hashes;

                var newHashes = listUpdate.AddingHashes ?? new List<byte[]>();

                if (listUpdate.FullUpdate)
                {
                    hashes.Clear();
                    hashes.AddRange(newHashes);
                }
                else
                {
                    if (listUpdate.RemovalsIndices != null)
                    {
                        foreach (var index in listUpdate.RemovalsIndices.OrderByDescending(x => x))
                        {
                            hashes.RemoveAt(index);
                        }
                    }

                    var comparer = new ByteArrayComparer();

                    foreach (var newHash in newHashes)
                    {
                        hashes.AddSorted(newHash, comparer);
                    }
                }

                SuspiciousLists[listUpdate.ThreatType].State = listUpdate.State;

#if !(NETSTANDARD1_0)
                var checksum = CryptographyHelper.GenerateSHA256(SuspiciousLists[listUpdate.ThreatType].Hashes.SelectMany(x=> x).ToArray());
                if (!checksum.SequenceEqual(listUpdate.Checksum))
                {
                    SuspiciousLists[listUpdate.ThreatType].State = null;
                }
#endif
            }

            Updated = now;
        }

        /// <summary>
        /// Search for prefixes of the given hashes
        /// </summary>
        /// <param name="threatType">Suspicious List type</param>
        /// <param name="hashes">List of hashes</param>
        /// <returns>List of hash prefixes</returns>
        public IEnumerable<byte[]> FindPrefixes(ThreatType threatType, IEnumerable<byte[]> hashes)
        {
            return hashes.Select(h => {
                var index = SuspiciousLists[threatType].Hashes.BinarySearch(h, new ByteArrayComparer(true));
                return index >= 0 ? SuspiciousLists[threatType].Hashes[index] : null;
            }).Where(x => x != null);
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

    public class ListUpdate
    {
        public ThreatType ThreatType { get; set; }
        public string State { get; set; }
        public bool FullUpdate { get; set; }
        public IEnumerable<byte[]> AddingHashes { get; set; }
        public IEnumerable<int> RemovalsIndices { get; set; }
        public byte[] Checksum { get; set; }
    }

    public enum ThreatType
    {
        SOCIAL_ENGINEERING,
        UNWANTED_SOFTWARE,
        MALWARE
    }

    public class ByteArrayComparer : IComparer<byte[]>
    {
        /// <summary>
        /// Allow to search prefixes by returning zero index if x is a prefix of y
        /// </summary>
        public bool SearchPrefixes { get; set; } = false;

        public ByteArrayComparer(bool searchPrefixes = false)
        {
            SearchPrefixes = searchPrefixes;
        }

        public int Compare(byte[] x, byte[] y)
        {
            int result;
            var min = Math.Min(x.Length, y.Length);
            for (int index = 0; index < min; index++)
            {
                result = x[index].CompareTo(y[index]);
                if (result != 0) return result;
            }
            if (SearchPrefixes && x.Length < y.Length)
            {
                return 0;
            }

            return x.Length.CompareTo(y.Length);
        }
    }
}
