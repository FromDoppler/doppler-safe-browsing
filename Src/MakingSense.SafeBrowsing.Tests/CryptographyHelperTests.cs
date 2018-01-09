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

#if !(NETSTANDARD1_0)
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
using TestCase = Xunit.InlineDataAttribute;
using Assert = MakingSense.SafeBrowsing.Tests.XUnitAssert;
#else
using NUnit.Framework;
#endif

namespace MakingSense.SafeBrowsing.Tests
{
    [TestFixture]
    public class CryptographyHelperTests
    {

#if DNXCORE50
        [Theory]
#endif
        [TestCase("abc", new byte[] { 0xba, 0x78, 0x16, 0xbf } )]
        [TestCase("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", new byte[] { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06 })]
        public void CryptographyHelper_should_generate_sha256_prefix(string input, byte[] expectedPrefix)
        {
            var prefixSize = expectedPrefix.Length;
            var output = CryptographyHelper.GenerateSHA256(input, prefixSize);
            Assert.AreEqual(prefixSize, output.Length);
            for (int i = 0; i < output.Length; i++)
            {
                Assert.AreEqual(expectedPrefix[i], output[i]);
            }
        }

#if DNXCORE50
        [Theory]
#endif
        [TestCase("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
        [TestCase("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")]
        public void CryptographyHelper_should_generate_sha256_string(string input, string expected)
        {
            var output = CryptographyHelper.GenerateSHA256String(input).ToLower();
            Assert.AreEqual(expected, output);
        }
    }
}
#endif