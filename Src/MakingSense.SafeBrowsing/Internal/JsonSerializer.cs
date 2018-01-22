#if !(NETSTANDARD1_0)
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.Internal
{
    public static class JsonSerializer
    {
        public static void WriteToJsonFile<T>(string filePath, T toSerialize, bool append = false) where T : new()
        {
            var serialized = Newtonsoft.Json.JsonConvert.SerializeObject(toSerialize);

#if !(NETSTANDARD1_0 || NET35 || NET40)
            using (var writer = (append ? File.AppendText(filePath) : File.CreateText(filePath)))
#else
            using (var writer = new StreamWriter(filePath, append))
#endif
            {
                writer.Write(serialized);
            }
        }

        public static T ReadFromJsonFile<T>(string filePath)
        {
            string fileContents;

            if (!File.Exists(filePath))
            {
                return default(T);
            }

#if !(NETSTANDARD1_0 || NET35 || NET40)
            fileContents = File.ReadAllText(filePath);
#else
            using (var reader = new StreamReader(filePath))
            {
                fileContents = reader.ReadToEnd();
                
            }
#endif
            return Newtonsoft.Json.JsonConvert.DeserializeObject<T>(fileContents);

        }
    }
}
#endif