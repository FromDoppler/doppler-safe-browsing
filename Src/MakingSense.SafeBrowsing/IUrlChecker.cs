using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing
{
    /// <summary>
    /// Common interface for different implementations of safe browsing checkers
    /// </summary>
    public interface IUrlChecker
    {
        /// <summary>
        /// Verify if a URL is safe or not
        /// </summary>
        /// <param name="url">URL to verify</param>
        /// <returns>Verification result</returns>
        SafeBrowsingStatus Check(string url);

        /// <summary>
        /// Verify if a URL is safe or not
        /// </summary>
        /// <param name="url">URL to verify</param>
        /// <returns>Verification result</returns>
        Task<SafeBrowsingStatus> CheckAsync(string url);
    }
}
