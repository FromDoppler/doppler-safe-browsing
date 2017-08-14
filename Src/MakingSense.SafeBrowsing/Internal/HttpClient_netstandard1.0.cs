#if (NETSTANDARD1_0)
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.Internal
{
    /// <summary>
    /// Custom HttpClient implementation
    /// </summary>
    public class HttpClient : IHttpClient
    {
        private const int BUFFER_SIZE = 1024;

        /// <inheritdoc />
        public async Task<SimplifiedHttpResponse> GetStringAsync(string url, string ifNoneMatch = null)
        {
            // TODO: Take into account ifNoneMatch value
            var response = await GetAsync(url);
            var buffer = new byte[BUFFER_SIZE];
            var sb = new StringBuilder();

            using (var stream = response.GetResponseStream())
            {
                bool finish = false;
                while (!finish)
                {
                    var read = await stream.ReadAsync(buffer, 0, BUFFER_SIZE);
                    if (read > 0)
                    {
                        sb.Append(Encoding.UTF8.GetString(buffer, 0, read));
                    }
                    else
                    {
                        finish = true;
                    }
                }
            }

            return new SimplifiedHttpResponse()
            {
                Body = sb.ToString()
                // TODO: Update NotModified and Etag values
            };
        }

        private Task<HttpWebResponse> GetAsync(string url)
        {
            var request = WebRequest.CreateHttp(url);
            return Task.Factory
                .FromAsync(request.BeginGetResponse, request.EndGetResponse, null)
                .ContinueWith(t => (HttpWebResponse)t.Result);
        }
    }
}
#endif