using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.SimpleRegex
{
    public class SimpleRegexRulesDouble : SimpleRegexRules
    {
        public int Count_Update { get; private set; } = 0;

        public override void Update(IEnumerable<Regex> initialBlacklist, string etag = null)
        {
            Count_Update++;
            base.Update(initialBlacklist, etag);
        }
    }
}
