using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.SimpleRegex
{
    /// <summary>
    /// Allow to download rules definition from HTTP and update them
    /// </summary>
    public class SimpleRegexRulesHttpUpdater
    {
        private readonly IHttpClient _httpClient;

        /// <summary>
        /// URL where rules are located
        /// </summary>
        public string Url { get; }

        /// <summary>
        /// Managed rules
        /// </summary>
        public SimpleRegexRules Rules { get; }

        /// <summary>
        /// Create a new instance with a new set of rules
        /// </summary>
        /// <param name="url"></param>
        /// <param name="httpClient">Optional alternative implementation of HttpClient</param>
        public SimpleRegexRulesHttpUpdater(string url, IHttpClient httpClient = null)
            : this(url, new SimpleRegexRules(), httpClient)
        {
        }

        /// <summary>
        /// Create a new instance for an already existent set of rules
        /// </summary>
        /// <param name="url"></param>
        /// <param name="rules"></param>
        /// /// <param name="httpClient">Optional alternative implementation of HttpClient</param>
        public SimpleRegexRulesHttpUpdater(string url, SimpleRegexRules rules, IHttpClient httpClient = null)
        {
            _httpClient = httpClient ?? new Internal.HttpClient();
            Url = url;
            Rules = rules;
        }

        /// <summary>
        /// Updates rules based on the remote resource
        /// </summary>
        /// <returns></returns>
        public async Task UpdateAsync()
        {
            var response = await _httpClient.GetStringAsync(Url, Rules.Etag);
            if (!response.NotModified)
            {
                var list = response.Body.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(x => x.Trim(new[] { ' ', '\t', '\x00EF', '\x00BB', '\x00BF' }))
                    .Where(x => x != string.Empty)
                    .Select(x => new Regex(x));
                Rules.Update(list, response.Etag);
            }
        }
    }
}
