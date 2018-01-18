using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MakingSense.SafeBrowsing.Internal
{
    public static class ListExtensions
    {
        public static void AddSorted(this List<byte[]> list, byte[] item, IComparer<byte[]> comparer)
        {
            if (list.Count == 0)
            {
                list.Add(item);
                return;
            }
            if (comparer.Compare(list[list.Count - 1], item) <= 0)
            {
                list.Add(item);
                return;
            }
            if (comparer.Compare(list[0], item) >= 0)
            {
                list.Insert(0, item);
                return;
            }
            int index = list.BinarySearch(item, comparer);
            if (index < 0)
                index = ~index;
            list.Insert(index, item);
        }
    }
}
