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

        public Task<string> GetStringAsync(string url)
        {
            return Internal.TaskUtilities.FromResult(Response_GetString);
        }
    }
}
