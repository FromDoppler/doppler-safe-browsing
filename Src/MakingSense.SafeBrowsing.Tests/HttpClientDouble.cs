using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.Tests
{
    public class HttpClientDouble : IHttpClient
    {
        public string Response_GetString { get; set; }

        public Task<SimplifiedHttpResponse> GetStringAsync(string url, string ifNoneMatch = null)
        {
            return Internal.TaskUtilities.FromResult(new SimplifiedHttpResponse()
            {
                Body = Response_GetString
                // TODO: support setting of NotModified and Etag values
            });
        }
    }
}
