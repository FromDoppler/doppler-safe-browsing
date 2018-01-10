#region License
// Copyright (c) 2017 Doppler Relay Team
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MakingSense.SafeBrowsing.Tests;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Threading;
#if DNXCORE50
using Xunit;
using Test = Xunit.FactAttribute;
using Assert = MakingSense.SafeBrowsing.Tests.XUnitAssert;
using TestCase = Xunit.InlineDataAttribute;
#else
using NUnit.Framework;
#endif

namespace MakingSense.SafeBrowsing.Tests
{
    [TestFixture]
    public class CanonicalUrlTests
    {

#if DNXCORE50
        [Theory]
#endif
        [TestCase("http://remove.this/", "http://remove.this/")]
        [TestCase("http://host/%25%32%35", "http://host/%25")]
        [TestCase("http://host/%25%32%35%25%32%35", "http://host/%25%25")]
        [TestCase("http://host/%2525252525252525", "http://host/%25")]
        [TestCase("http://host/asdf%25%32%35asd", "http://host/asdf%25asd")]
        [TestCase("http://host/%%%25%32%35asd%%", "http://host/%25%25%25asd%25%25")]
        [TestCase("http://www.google.com/", "http://www.google.com/")]
        [TestCase("http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/", "http://168.188.99.26/.secure/www.ebay.com/")]
        [TestCase("http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/", "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/")]
        [TestCase("http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B", "http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+")]
        [TestCase("http://3279880203/blah", "http://195.127.0.11/blah")]
        [TestCase("http://www.google.com/blah/..", "http://www.google.com/")]
        [TestCase("www.google.com/", "http://www.google.com/")]
        [TestCase("www.google.com", "http://www.google.com/")]
        [TestCase("http://www.evil.com/blah#frag", "http://www.evil.com/blah")]
        [TestCase("http://www.GOOgle.com/", "http://www.google.com/")]
        [TestCase("http://www.google.com.../", "http://www.google.com/")]
        [TestCase("http://www.google.com/foo\tbar\rbaz\n2", "http://www.google.com/foobarbaz2")]
        [TestCase("http://www.google.com/q?", "http://www.google.com/q?")]
        [TestCase("http://www.google.com/q?r?", "http://www.google.com/q?r?")]
        [TestCase("http://www.google.com/q?r?s", "http://www.google.com/q?r?s")]
        [TestCase("http://evil.com/foo#bar#baz", "http://evil.com/foo")]
        [TestCase("http://evil.com/foo;", "http://evil.com/foo;")]
        [TestCase("http://evil.com/foo?bar;", "http://evil.com/foo?bar;")]
        [TestCase("http://\x01\x80.com/", "http://%01%80.com/")]
        [TestCase("http://notrailingslash.com", "http://notrailingslash.com/")]
        [TestCase("http://www.gotaport.com:1234/", "http://www.gotaport.com/")]
        [TestCase("  http://www.google.com/  ", "http://www.google.com/")]
        [TestCase("http:// leadingspace.com/", "http://%20leadingspace.com/")]
        [TestCase("http://%20leadingspace.com/", "http://%20leadingspace.com/")]
        [TestCase("%20leadingspace.com/", "http://%20leadingspace.com/")]
        [TestCase("https://www.securesite.com/", "https://www.securesite.com/")]
        [TestCase("http://host.com/ab%23cd", "http://host.com/ab%23cd")]
        [TestCase("http://host.com//twoslashes?more//slashes", "http://host.com/twoslashes?more//slashes")]
        public void CanonicalUrl_Create_should_return_expectedValue(string input, string expected)
        {
            var canonicalUrl = CanonicalUrl.Create(input);
            Assert.AreEqual(expected, canonicalUrl.ToString());
        }
    }
}
