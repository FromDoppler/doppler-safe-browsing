#if !(NETSTANDARD1_0)
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
using MakingSense.SafeBrowsing.GoogleSafeBrowsing;
#if DNXCORE50
using Xunit;
using Test = Xunit.FactAttribute;
using Assert = MakingSense.SafeBrowsing.Tests.XUnitAssert;
#else
using NUnit.Framework;
#endif

namespace MakingSense.SafeBrowsing.Tests.GoogleSafeBrowsing
{
    [TestFixture]
    public class GoogleSafeBrowsingCheckerTests : TestFixtureBase
    {
        [Test]
        public void GoogleSafeBrowsingChecker_Check_should_identify_dangerous_urls()
        {
            // Arrange
            var database = new GoogleSafeBrowsingDatabase();
            database.Update(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1000), CreateListUpdatesData());
            var sut = new GoogleSafeBrowsingChecker(database);
            var url = "http://malware.testing.google.test/testing/malware/";

            // Act
            var result = sut.Check(url);

            // Assert
            Assert.AreEqual(url, result.Url);
            Assert.IsFalse(result.IsSafe);
            Assert.AreEqual(ThreatType.Malware, result.ThreatType);
        }

        [Test]
        public void GoogleSafeBrowsingChecker_Check_should_identify_safe_urls()
        {
            // Arrange
            var database = new GoogleSafeBrowsingDatabase();
            database.Update(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1000), CreateListUpdatesData());
            var sut = new GoogleSafeBrowsingChecker(database);
            var url = "http://some.url/safe";

            // Act
            var result = sut.Check(url);

            // Assert
            Assert.AreEqual(url, result.Url);
            Assert.IsTrue(result.IsSafe);
            Assert.AreEqual(ThreatType.NoThreat, result.ThreatType);
        }

        [Test]
        public void GoogleSafeBrowsingChecker_CheckAsync_should_identify_dangerous_urls()
        {
            // Arrange
            var database = new GoogleSafeBrowsingDatabase();
            database.Update(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1000), CreateListUpdatesData());
            var sut = new GoogleSafeBrowsingChecker(database);
            var url = "http://malware.testing.google.test/testing/malware/";

            // Act
            var result = sut.CheckAsync(url).Result;

            // Assert
            Assert.AreEqual(url, result.Url);
            Assert.IsFalse(result.IsSafe);
            Assert.AreEqual(ThreatType.Malware, result.ThreatType);
        }

        [Test]
        public void GoogleSafeBrowsingChecker_CheckAsync_should_identify_safe_urls()
        {
            // Arrange
            var database = new GoogleSafeBrowsingDatabase();
            database.Update(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1000), CreateListUpdatesData());
            var sut = new GoogleSafeBrowsingChecker(database);
            var url = "http://some.url/safe";

            // Act
            var result = sut.CheckAsync(url).Result;

            // Assert
            Assert.AreEqual(url, result.Url);
            Assert.IsTrue(result.IsSafe);
            Assert.AreEqual(ThreatType.NoThreat, result.ThreatType);
        }

        [Test]
        public void GoogleSafeBrowsingChecker_should_respond_to_rules_updating()
        {
            // Arrange
            var database = new GoogleSafeBrowsingDatabase();
            database.Update(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1000), CreateListUpdatesData());
            var sut = new GoogleSafeBrowsingChecker(database);
            var url = "http://malware.testing.google.test/testing/malware/";
            Assert.IsFalse(sut.Check(url).IsSafe);

            // Act
            database.Update(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1000), new List<ListUpdate> {
                new ListUpdate
                {
                    FullUpdate = false,
                    Checksum = new byte[]{132,222,30,94,171,161,143,30,195,17,230,181,65,238,8,79,83,69,210,33,43,247,143,92,163,63,134,155,127,14,155,211},
                    State = "new-state",
                    ThreatType = SafeBrowsing.GoogleSafeBrowsing.ThreatType.MALWARE,
                    RemovalsIndices = new List<int>{ 2 }
                }
            });
            var result = sut.Check(url);

            // Assert
            Assert.AreEqual(url, result.Url);
            Assert.AreEqual(ThreatType.NoThreat, result.ThreatType);
            Assert.IsTrue(result.IsSafe);
        }

        private List<ListUpdate> CreateListUpdatesData()
        {
            return new List<ListUpdate>
            {
                new ListUpdate
                {
                    FullUpdate = true,
                    Checksum = new byte[]{ 50, 221, 200, 121, 47, 239, 218, 243, 179, 54, 93, 120, 158, 143, 28, 232, 226, 198, 16, 144, 25, 246, 48, 88, 155, 24, 245, 149, 217, 196, 170, 153 },
                    State = "first-state",
                    ThreatType = SafeBrowsing.GoogleSafeBrowsing.ThreatType.MALWARE,
                    AddingHashes = new List<byte[]>{
                        new byte[]{ 0, 12, 32, 123},
                        new byte[]{ 36, 2, 5, 43},
                        new byte[]{ 81, 134, 64, 69}, // http://malware.testing.google.test/testing/malware/ prefix
                        new byte[]{ 156, 12, 54, 3},
                    }
                },
            };
        }
    }
}
#endif