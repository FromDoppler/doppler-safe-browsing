#if !(NET35 || NET40 || NETSTANDARD1_0)

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
using Google.Apis.Safebrowsing.v4.Data;
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
    public class GoogleSafeBrowsingUpdaterTests : TestFixtureBase
    {
        [Test]
        public void GoogleSafeBrowsingUpdater_should_update_lists_with_initial_data()
        {
            // Arrange

            var service = new SafeBrowsingServiceDouble();
            var response = CreateFullUpdateResponse();
            service.Setup_FetchThreatListUpdatesAsync(CreateFullUpdateResponse());
            var database = new GoogleSafeBrowsingDatabase();
            var sut = new GoogleSafeBrowsingUpdater(new GoogleSafeBrowsingConfiguration(), service, database);

            // Act
            sut.UpdateAsync().Wait();

            // Assert
            Assert.IsTrue(database.MinimumWaitDuration.HasValue);
            Assert.AreEqual(1625.154, database.MinimumWaitDuration.Value.TotalSeconds);
            Assert.IsFalse(database.AllowRequest);
            Assert.IsNotNull(database.Updated);
            Assert.AreEqual("malware-sate-1", database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.MALWARE].State);
            Assert.AreEqual(2, database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.MALWARE].Hashes.Count);
            Assert.AreEqual("social-eng-sate-1", database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.SOCIAL_ENGINEERING].State);
            Assert.AreEqual(1, database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.SOCIAL_ENGINEERING].Hashes.Count);
            Assert.AreEqual("unwanted-sw-sate-1", database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.UNWANTED_SOFTWARE].State);
            Assert.AreEqual(0, database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.UNWANTED_SOFTWARE].Hashes.Count);

        }

        [Test]
        public void GoogleSafeBrowsingUpdater_should_update_lists_with_partial_data()
        {
            // Arrange
            var service = new SafeBrowsingServiceDouble();
            var response = CreateFullUpdateResponse();
            response.MinimumWaitDuration = null;
            service.Setup_FetchThreatListUpdatesAsync(response);
            var database = new GoogleSafeBrowsingDatabase();
            var sut = new GoogleSafeBrowsingUpdater(new GoogleSafeBrowsingConfiguration(), service, database);

            // Act
            sut.UpdateAsync().Wait();
            service.Setup_FetchThreatListUpdatesAsync(CreatePartialUpdateResponse());
            sut.UpdateAsync().Wait();

            // Assert
            Assert.IsTrue(database.MinimumWaitDuration.HasValue);
            Assert.AreEqual(1452.62, database.MinimumWaitDuration.Value.TotalSeconds);
            Assert.IsNotNull(database.Updated);
            Assert.AreEqual("malware-sate-2", database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.MALWARE].State);
            Assert.AreEqual(2, database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.MALWARE].Hashes.Count);
            Assert.AreEqual("social-eng-sate-1", database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.SOCIAL_ENGINEERING].State);
            Assert.AreEqual(1, database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.SOCIAL_ENGINEERING].Hashes.Count);
            Assert.AreEqual("unwanted-sw-sate-2", database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.UNWANTED_SOFTWARE].State);
            Assert.AreEqual(1, database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.UNWANTED_SOFTWARE].Hashes.Count);

        }

        [Test]
        public void GoogleSafeBrowsingUpdater_should_empty_state_when_invalidChecksum()
        {
            // Arrange
            var service = new SafeBrowsingServiceDouble();
            var response = CreateFullUpdateResponse();
            response.MinimumWaitDuration = null;
            service.Setup_FetchThreatListUpdatesAsync(response);
            var database = new GoogleSafeBrowsingDatabase();
            var sut = new GoogleSafeBrowsingUpdater(new GoogleSafeBrowsingConfiguration(), service, database);
            sut.UpdateAsync().Wait();
            var update = CreatePartialUpdateResponse();
            update.ListUpdateResponses.First(x=> x.ThreatType == "MALWARE").Checksum.Sha256 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

            //Act
            service.Setup_FetchThreatListUpdatesAsync(update);
            sut.UpdateAsync().Wait();

            // Assert
            Assert.IsTrue(database.MinimumWaitDuration.HasValue);
            Assert.AreEqual(1452.62, database.MinimumWaitDuration.Value.TotalSeconds);
            Assert.IsNotNull(database.Updated);
            Assert.IsNull(database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.MALWARE].State);
            Assert.AreEqual(2, database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.MALWARE].Hashes.Count);
            Assert.AreEqual("social-eng-sate-1", database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.SOCIAL_ENGINEERING].State);
            Assert.AreEqual(1, database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.SOCIAL_ENGINEERING].Hashes.Count);
            Assert.AreEqual("unwanted-sw-sate-2", database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.UNWANTED_SOFTWARE].State);
            Assert.AreEqual(1, database.SuspiciousLists[SafeBrowsing.GoogleSafeBrowsing.ThreatType.UNWANTED_SOFTWARE].Hashes.Count);

        }

        [Test]
        public void GoogleSafeBrowsingUpdater_should_enter_backOff_mode_when_apiException()
        {
            // Arrange
            var service = new SafeBrowsingServiceDouble();
            service.Setup_FetchThreatListUpdatesAsync(new Exception());
            var database = new GoogleSafeBrowsingDatabase();
            var sut = new GoogleSafeBrowsingUpdater(new GoogleSafeBrowsingConfiguration(), service, database);

            // Act
            try
            {
                sut.UpdateAsync().Wait();
                Assert.Fail("Should throw the exception after enter back off mode");
            }
            catch (Exception)
            {
                // Assert
                Assert.IsTrue(database.BackOffMode);
                Assert.AreEqual(1, database.BackOffRetryNumber);
                Assert.IsFalse(database.AllowRequest);
            }
        }

        private FetchThreatListUpdatesResponse CreateFullUpdateResponse()
        {
            return new FetchThreatListUpdatesResponse {
                MinimumWaitDuration = "1625.154s", //27:5.154
                ListUpdateResponses = new List<ListUpdateResponse>
                {
                    new ListUpdateResponse
                    {
                        ThreatType = "MALWARE",
                        NewClientState = "malware-sate-1",
                        ResponseType = "FULL_UPDATE",
                        Additions = new List<ThreatEntrySet>
                        {
                            new ThreatEntrySet
                            {
                                RawHashes = new RawHashes
                                {
                                    RawHashesValue = "IL5HqwT2c6bltw==",
                                    PrefixSize = 5
                                }
                            }
                        },
                        Checksum = new Checksum
                        {
                            Sha256 = "DagMoQ/h1Qm2BUfStEKs7uBw89Sjr/CAIyHaBKLNA+k="
                        }
                    },
                    new ListUpdateResponse
                    {
                        ThreatType = "SOCIAL_ENGINEERING",
                        NewClientState = "social-eng-sate-1",
                        ResponseType = "FULL_UPDATE",
                        Additions = new List<ThreatEntrySet>
                        {
                            new ThreatEntrySet
                            {
                                RawHashes = new RawHashes
                                {
                                    RawHashesValue = "rnGLoQ==",
                                    PrefixSize = 4
                                }
                            }
                        },
                        Checksum = new Checksum
                        {
                            Sha256 = "YSgoRtsRlgHDqDA3LAhM1gegEpEzs1TjzU33vqsR8iM="
                        }
                    },
                    new ListUpdateResponse
                    {
                        ThreatType = "UNWANTED_SOFTWARE",
                        NewClientState = "unwanted-sw-sate-1",
                        ResponseType = "FULL_UPDATE",
                        Checksum = new Checksum
                        {
                            Sha256 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
                        }
                    }
                }
            };
        }

        private FetchThreatListUpdatesResponse CreatePartialUpdateResponse()
        {
            return new FetchThreatListUpdatesResponse
            {
                MinimumWaitDuration = "1452.62s",
                ListUpdateResponses = new List<ListUpdateResponse>
                {
                    new ListUpdateResponse
                    {
                        ThreatType = "MALWARE",
                        NewClientState = "malware-sate-2",
                        ResponseType = "PARTIAL_UPDATE",
                        Additions = new List<ThreatEntrySet>
                        {
                            new ThreatEntrySet
                            {
                                RawHashes = new RawHashes
                                {
                                    RawHashesValue = "WwuJdQ==",
                                    PrefixSize = 4
                                }
                            }
                        },
                        Removals = new List<ThreatEntrySet>
                        {
                            new ThreatEntrySet
                            {
                                RawIndices = new RawIndices
                                {
                                    Indices = new List<int?>{ 0 }
                                }
                            }
                        },
                        Checksum = new Checksum
                        {
                            Sha256 = "3E7yWvipb33i6tVlw457FXDozvjhE1CENPYNOTDhI2s="
                        }
                    },
                    new ListUpdateResponse
                    {
                        ThreatType = "SOCIAL_ENGINEERING",
                        NewClientState = "social-eng-sate-1",
                        ResponseType = "PARTIAL_UPDATE",
                        Checksum = new Checksum
                        {
                            Sha256 = "YSgoRtsRlgHDqDA3LAhM1gegEpEzs1TjzU33vqsR8iM="
                        }
                    },
                    new ListUpdateResponse
                    {
                        ThreatType = "UNWANTED_SOFTWARE",
                        NewClientState = "unwanted-sw-sate-2",
                        ResponseType = "FULL_UPDATE",
                        Additions = new List<ThreatEntrySet>
                        {
                            new ThreatEntrySet
                            {
                                RawHashes = new RawHashes
                                {
                                    RawHashesValue = "5eOrwQ==",
                                    PrefixSize = 4
                                }
                            }
                        },
                        Checksum = new Checksum
                        {
                            Sha256 = "1InO6kPzdG46JBXoFyUBHe667+wHHcACahYSb/njIrg="
                        }
                    }
                }
            };
        }
    }
}

#endif