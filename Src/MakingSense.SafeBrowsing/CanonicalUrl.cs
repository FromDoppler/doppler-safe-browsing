using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing
{
    public class CanonicalUrl
    {
        public string Host { get; private set; }

        public string Schema { get; private set; }

        public string Path { get; private set; }

        public string Query { get; private set; }

        public override string ToString()
        {
            return Schema + Host + Path + Query;
        }

        private CanonicalUrl() { }

        public static CanonicalUrl Create(string url)
        {
            // remove tab (0x09), CR (0x0d), and LF (0x0a) characters from the URL
            Regex escChars = new Regex(@"\r|\t|\n|\v");
            url = escChars.Replace(url, String.Empty);

            // remove leading and trailing whitespace
            url = url.Trim(' ');

            // remove fragment
            Regex frag = new Regex(@"#.*");
            url = frag.Replace(url, String.Empty);

            // repeatedly unescape
            url = Unencode(url);

            Regex urlReg = new Regex(@"^((?:http|https|ftp)\://)?(.+?)(:.*?)?(?:(/.*?)|)(\?.+)?$");
            Match urlMatch = urlReg.Match(url);

            if (!urlMatch.Success)
                throw new ArgumentException("Supplied URL was not in valid format " + url);

            var schema = urlMatch.Groups[1].Value;
            if (String.IsNullOrEmpty(schema))
                schema = "http://";

            var host = urlMatch.Groups[2].Value;

            // remove all leading and trailing dots
            host = host.Trim('.');

            // replace consecutive dots with a single dot
            Regex dots = new Regex(@"\.\.+");
            host = dots.Replace(host, String.Empty);

            // lower case
            host = host.ToLowerInvariant();

            // normalize it to 4 dot-separated decimal values if the can be parsed as an IP address
            long intHost = -1;
            if (Int64.TryParse(host, out intHost))
            {
                host = String.Format("{0}.{1}.{2}.{3}", (intHost >> 24) & 255,
                                                        (intHost >> 16) & 255,
                                                        (intHost >> 8) & 255,
                                                        (intHost) & 255);
            }

            var path = urlMatch.Groups[4].Value;

            // replace "/./" with "/"
            Regex seq1 = new Regex(@"(?:/\./)");
            path = seq1.Replace(path, @"/");

            // remove "/../" along with the preceding path component
            Regex seq2 = new Regex(@"/.+?/\.\./?");
            path = seq2.Replace(path, String.Empty);

            // Replace runs of consecutive slashes with a single slash character.
            Regex seq3 = new Regex(@"(?://+)");
            path = seq3.Replace(path, @"/");

            if (String.IsNullOrEmpty(path))
                path = "/";

            var query = urlMatch.Groups[5].Value;

            return new CanonicalUrl()
            {
                Schema = Encode(schema),
                Host = Encode(host),
                Path = Encode(path),
                Query = Encode(query)
            };
        }

        /// <summary>
        /// Generate the url prefix/suffix combinations
        /// <para>The client will form up to 30 different possible host suffix and path prefix combinations. 
        /// These combinations use only the host and path components of the URL.
        /// The scheme, username, password, and port are disregarded. 
        /// If the URL includes query parameters, then at least one combination will include the full path and query parameters.</para>
        /// </summary>
        /// <returns></returns>
        public IList<string> GeneratePrefixSuffixPatterns()
        {
            var hosts = GetPrefixes();
            var paths = GetSufixes();

            return hosts.SelectMany(h => paths.Select(p => h + p)).ToList(); 
        }

        /**
         * For the path, the client will try at most six different strings. They are:
         * - The exact path of the URL, including query parameters.
         * - The exact path of the URL, without query parameters. 
         * - The four paths formed by starting at the root (/) and successively appending path components, including a trailing slash.
         * */
        private List<string> GetSufixes()
        {
            var paths = new List<string>();

            if (!string.IsNullOrEmpty(this.Query))
            {
                paths.Add(this.Path + this.Query);
            }

            paths.Add(this.Path);

            if(this.Path == "/")
            {
                return paths;
            }

            paths.Add("/");

            var pathComp = this.Path.Trim('/').Split('/');

            if (pathComp.Length > 1)
            {
                // take up to 3 path components and always ignore the last component (full path is already added)
                var maxCount = pathComp.Length > 3 ? 3 : pathComp.Length - 1;

                for (int i = 1; i <= maxCount; i++)
                {
                    paths.Add("/" + string.Join("/", pathComp.Take(i).ToArray()) + "/");
                }
            }

            return paths;
        }

        /**
         * For the host, the client will try at most five different strings. They are:
         * - The exact hostname in the URL.
         * - Up to four hostnames formed by starting with the last five components and successively removing the leading component. 
         *   The top-level domain can be skipped. These additional hostnames should not be checked if the host is an IP address.
         * */
        private List<string> GetPrefixes()
        {
            var hosts = new List<string> { this.Host };

            Regex ip = new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
            if (ip.IsMatch(this.Host))
            {
                return hosts;
            }

            var hostComp = this.Host.Split('.');
            if (hostComp.Length > 2)
            {
                // ignore components other than the last 5 ones
                var startPos = hostComp.Length > 5 ? hostComp.Length - 5 : 1;
                var lastComponents = hostComp.Skip(startPos);

                for (int i = 0; i < lastComponents.Count() - 1; i++)
                {
                    hosts.Add(string.Join(".", lastComponents.Skip(i).ToArray()));
                }
            }

            return hosts;
        }

        private static string Encode(string url)
        {
            var sb = new StringBuilder();
            var cha = url.ToCharArray();
            for (int i = 0; i < url.Length; i++)
            {
                if (cha[i] <= 32 || cha[i] >= 127 || cha[i] == '#' || cha[i] == '%')
                    sb.Append("%" + ((int)cha[i]).ToString("X2"));
                else
                    sb.Append(cha[i]);
            }

            return sb.ToString();
        }

        private static string Unencode(string url)
        {
            Regex unescape = new Regex(@"%([0-9a-fA-F]{2})");
            MatchCollection matches = unescape.Matches(url);
            StringBuilder sb = null;
            int prev = 0;
            byte hex;
            while (matches.Count > 0)
            {
                sb = new StringBuilder();

                prev = 0;
                foreach (Match match in matches)
                {
                    sb.Append(url.Substring(prev, match.Index - prev));
                    hex = Byte.Parse(match.Groups[1].Value, System.Globalization.NumberStyles.HexNumber);
                    sb.Append((char)hex);
                    prev = match.Index + match.Length;
                }
                sb.Append(url.Substring(prev));
                url = sb.ToString();
                matches = unescape.Matches(url);
            }

            return url;
        }
    }
}
