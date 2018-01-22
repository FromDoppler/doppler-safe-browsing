using MakingSense.SafeBrowsing;
using MakingSense.SafeBrowsing.GoogleSafeBrowsing;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace TestConsoleCli
{
    class Program
    {
        static void Main(string[] args)
        {
            var config = new GoogleSafeBrowsingConfiguration()
            {
                ApiKey = "insert-api-key-here",
                ClientId = "DopplerRelay",
                ClientVersion = "1.0.0"
            };

            var database = GoogleSafeBrowsingDatabase.Initialize(@"C:\test_relay\google-safebrowsing-database.json");
            var updater = new GoogleSafeBrowsingUpdater(config, database: database);
            var checker = new GoogleSafeBrowsingChecker(updater.Database);

            updater.UpdatePeriodically(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(30));

            if (!database.Updated.HasValue)
            {
                Console.WriteLine(">> Getting data from API...");
                while (!database.Updated.HasValue)
                {
                    Thread.Sleep(3000);
                }
            }

            // Checking urls from list

            Console.WriteLine(">> Checking urls...");

            var urlsList = new List<string> {
               "http://malware.testing.google.test/testing/malware/",
               "http://resolutioncentrepaypal.ga/test/example?query1=1&query2=2#something",
               "https://factura.movistar.com.ar/cuadro/?f=tWcAlixN%2fRGI84lyST1omS1vLDwAoNCP0Q6S3ovH3qavLJW%2bKqSLQ8AEs0ciG056",
               "http://bit.ly/2mIzNIF?bbatendimientos464565526",
               "http://scoreapaydayloan.com/",
               "http://rmlnk.primalnssupport.com/rd/?i=rl_A1572495_594090881_954_4_11167_0_A_105381"
            };

            foreach (var url in urlsList)
            {
                var result = checker.Check(url);
                Console.WriteLine($"Checking {url}");
                Console.WriteLine(result.IsSafe ? "SAFE" : result.ThreatType.ToString());
                Console.WriteLine();
            }

            // Checking urls from csv

            Console.WriteLine(">> Reading url list from disk...");
            Dictionary<string, string> urlsFromFile = GetUrlListToCheck(@"C:\test_relay\prod-links-from-20180115.csv");

            Console.WriteLine(">> Checking urls...");
            CheckUrlsAndOutputResults(checker, urlsFromFile, @"C:\test_relay\output.csv");

            Console.WriteLine();
            Console.WriteLine("Press any key to exit.");

            Console.ReadKey();
        }

        private static void CheckUrlsAndOutputResults(GoogleSafeBrowsingChecker checker, Dictionary<string, string> urls, string path)
        {
            using (StreamWriter sw = new StreamWriter(path, false))
            {
                sw.WriteLine($"Id,Url,ThreatType");
                var count = 0;

                foreach (var line in urls)
                {
                    count++;

                    var result = checker.Check(line.Value);
                    if (!result.IsSafe)
                    {
                        sw.WriteLine($"{line.Key},{result.Url},{result.ThreatType}");
                    }

                    if (count % 1000 == 0)
                    {
                        Console.Write($".");
                    }
                }
            }
        }

        private static Dictionary<string, string> GetUrlListToCheck(string path)
        {
            var urls = new Dictionary<string, string>();

            using (StreamReader sr = new StreamReader(path))
            {
                int i = -1;
                string currentLine;

                //currentLine will be null when the StreamReader reaches the end of file
                while ((currentLine = sr.ReadLine()) != null)
                {
                    i++;
                    if (i == 0)
                    {
                        continue;
                    }

                    // Cols = Id, CreatedAt, Url
                    var cols = currentLine.Split(',');

                    if (cols.Length < 3)
                        continue;

                    var id = cols[0];
                    var url = cols[2];

                    urls.TryAdd(id, url);
                }
            }

            return urls;
        }        
    }
}
