#if (!NETSTANDARD1_0)
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.Internal
{
    /// <summary>
    /// Wrapper around System.Net.Http.HttpClient to allow easily implement a compatible version for netstandard1.0
    /// </summary>
    public class HttpClient : IHttpClient
    {

        private static System.Net.Http.HttpClient _httpClient = new System.Net.Http.HttpClient();

        /// <inheritdoc />
        public Task<string> GetStringAsync(string url)
        {
            return _httpClient.GetStringAsync(url);
        }
    }
}
#endif
