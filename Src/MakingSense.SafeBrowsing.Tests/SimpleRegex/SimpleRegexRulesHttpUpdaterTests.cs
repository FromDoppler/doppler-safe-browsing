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
#if DNXCORE50
using Xunit;
using Test = Xunit.FactAttribute;
using Assert = MakingSense.SafeBrowsing.Tests.XUnitAssert;
#else
using NUnit.Framework;
#endif

namespace MakingSense.SafeBrowsing.SimpleRegex
{
    [TestFixture]
    public class SimpleRegexRulesHttpUpdaterTests : TestFixtureBase
    {
        [Test]
        public void SimpleRegexRulesHttpUpdater_should_update_rules_reading_remote_file_real_request()
        {
            // Arrange
            var realUrl = "https://raw.githubusercontent.com/MakingSense/safe-browsing/resources/links-blacklist.txt";
            var rules = new SimpleRegexRules();
            var sut = new SimpleRegexRulesHttpUpdater(realUrl, rules);
            Assert.IsFalse(rules.Blacklist.Any());

            // Act
            sut.UpdateAsync().Wait();

            // Assert
            Assert.IsTrue(rules.Blacklist.Any());
        }

        [Test]
        public void SimpleRegexRulesHttpUpdater_should_update_rules()
        {
            // Arrange
            var rules = new SimpleRegexRulesDouble();
            var anyUrl = "http://example.com/rules";
            var httpClient = new HttpClientDouble();
            httpClient.Setup_GetString(".*");
            var sut = new SimpleRegexRulesHttpUpdater(anyUrl, rules, httpClient);
            Assert.AreEqual(0, rules.Count_Update);

            // Act
            sut.UpdateAsync().Wait();

            // Assert
            Assert.AreEqual(1, rules.Count_Update);
        }

        [Test]
        public void SimpleRegexRulesHttpUpdater_should_not_update_rules_when_remote_file_not_found_real_request()
        {
            // Arrange
            var notFoundUrl = "https://raw.githubusercontent.com/MakingSense/safe-browsing/resources/notfound";
            var originalRegex = new Regex(".*");
            var rules = new SimpleRegexRules(new[] { originalRegex });
            var sut = new SimpleRegexRulesHttpUpdater(notFoundUrl, rules);
            Assert.AreEqual(1, rules.Blacklist.Count);

            // Act
            try
            {
                sut.UpdateAsync().Wait();

                // Assert
                Assert.Fail("Update should throw exception when URL not found");
            }
            catch
            {
                // Assert
                Assert.AreEqual(1, rules.Blacklist.Count);
                Assert.AreEqual(originalRegex, rules.Blacklist.First());
            }
        }

        [Test]
        public void SimpleRegexRulesHttpUpdater_should_not_update_rules_when_remote_file_not_found()
        {
            // Arrange
            var anyUrl = "http://example.com/notfound";
            var rules = new SimpleRegexRulesDouble();
            var httpClient = new HttpClientDouble();
#if (!NETSTANDARD1_0)
            httpClient.Setup_GetString(new System.Net.Http.HttpRequestException("404 (Not Found)."));
#else
            httpClient.Setup_GetString(new System.Net.WebException("(404) Not Found."));
#endif
            var sut = new SimpleRegexRulesHttpUpdater(anyUrl, rules, httpClient);

            // Act
            try
            {
                sut.UpdateAsync().Wait();

                // Assert
                Assert.Fail("Update should throw exception when URL not found");
            }
            catch
            {
                // Assert
                Assert.AreEqual(0, rules.Count_Update);
            }
        }

        [Test]
        public void SimpleRegexRulesHttpUpdater_should_read_all_remote_lines()
        {
            // Arrange
            var anyUrl = "http://example.com/links-blacklist.txt";
            var httpClient = new HttpClientDouble();
            httpClient.Setup_GetString("0\r\n  1  \n2\r\n3");
            var sut = new SimpleRegexRulesHttpUpdater(anyUrl, httpClient);
            Assert.IsFalse(sut.Rules.Blacklist.Any());

            // Act
            sut.UpdateAsync().Wait();

            // Assert
            Assert.IsTrue(sut.Rules.Blacklist.Any());
            Assert.AreEqual(4, sut.Rules.Blacklist.Count);
            Assert.AreEqual("0", sut.Rules.Blacklist[0].ToString());
            Assert.AreEqual("1", sut.Rules.Blacklist[1].ToString());
            Assert.AreEqual("2", sut.Rules.Blacklist[2].ToString());
            Assert.AreEqual("3", sut.Rules.Blacklist[3].ToString());
        }

        [Test]
        public void SimpleRegexRulesHttpUpdater_should_not_update_list_when_response_is_not_modified()
        {
            // Arrange
            var anyUrl = "http://example.com/links-blacklist.txt";
            var originalRegex = new Regex(".*");
            var rules = new SimpleRegexRules(new[] { originalRegex });
            var originalList = rules.Blacklist;
            var httpClient = new HttpClientDouble();
            httpClient.Setup_GetString(new SimplifiedHttpResponse()
            {
                Body = "0\r\n  1  \n2\r\n3",
                NotModified = true
            });
            var sut = new SimpleRegexRulesHttpUpdater(anyUrl, rules, httpClient);
            Assert.AreEqual(1, rules.Blacklist.Count);

            // Act
            sut.UpdateAsync().Wait();

            // Assert
            Assert.AreEqual(1, rules.Blacklist.Count);
            Assert.AreEqual(originalRegex, rules.Blacklist.First());
            Assert.AreSame(originalList, rules.Blacklist);
        }
    }
}
