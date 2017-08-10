using MakingSense.SafeBrowsing.Internal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.SimpleRegex
{
    /// <summary>
    /// Simple implementation of Safe Browsing Checker that uses a list of regular expressions
    /// </summary>
    public class SimpleRegexUrlChecker : IUrlChecker
    {
        private readonly List<Regex> _blacklist = new List<Regex>();

        /// <summary>
        /// Create a new instance based on a list of patterns
        /// </summary>
        /// <param name="blacklistPatterns"></param>
        public SimpleRegexUrlChecker(IEnumerable<string> blacklistPatterns)
            : this(blacklistPatterns.Select(x => new Regex(x)))
        {
        }

        /// <summary>
        /// Create a new instance based on a list of regular expressions
        /// </summary>
        /// <param name="blacklist"></param>
        public SimpleRegexUrlChecker(IEnumerable<Regex> blacklist)
        {
            _blacklist.AddRange(blacklist);
        }

        /// <inheritdoc />
        public SafeBrowsingStatus Check(string url) =>
            new SafeBrowsingStatus(
                url,
                _blacklist.Any(r => r.IsMatch(url)) ? ThreatType.Unknow : ThreatType.NoThreat);

        /// <inheritdoc />
        public Task<SafeBrowsingStatus> CheckAsync(string url) =>
            TaskUtilities.FromResult(Check(url));
    }
}
