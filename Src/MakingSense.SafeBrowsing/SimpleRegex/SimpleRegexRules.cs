using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.SimpleRegex
{
    /// <summary>
    /// Set of rules necessary to evaluate links by SimpleRegexUrlChecker
    /// </summary>
    public class SimpleRegexRules
    {
        private static readonly ReadOnlyCollection<Regex> EmptyCollection = new ReadOnlyCollection<Regex>(new List<Regex>());

        /// <summary>
        /// Collection of regular expressions that represent dangerous URLs
        /// </summary>
        public ReadOnlyCollection<Regex> Blacklist { get; private set; }

        /// <summary>
        /// Create SimpleRegexRules without any blacklist entry
        /// </summary>
        public SimpleRegexRules()
        {
            Blacklist = EmptyCollection;
        }

        /// <summary>
        /// Create SimpleRegexRules with specified blacklist entry
        /// </summary>
        /// <param name="initialBlacklist"></param>
        public SimpleRegexRules(IEnumerable<Regex> initialBlacklist)
        {
            Update(initialBlacklist);
        }

        /// <summary>
        /// Update current blacklist with a new one
        /// </summary>
        /// <param name="initialBlacklist"></param>
        public void Update(IEnumerable<Regex> initialBlacklist)
        {
            Blacklist = new ReadOnlyCollection<Regex>(initialBlacklist.ToList());
        }
    }
}
