using System.Text;

namespace packageVulnerabilities.Utils
{
    public static class Helper
    {
        public static string FromBase64(string data)
        {
            if (string.IsNullOrEmpty(data)) return data;
            var bytes = Convert.FromBase64String(data);
            return Encoding.UTF8.GetString(bytes);
        }

        public static List<Tuple<string, string>> GetVersionsAndSigns(string exp)
        {
            string[] expDivided = exp.Split(',');
            List<Tuple<string, string>> versionAndSign = new List<Tuple<string, string>>();

            foreach (var expDividedItem in expDivided)
            {
                string trimmedExpDividedItem = expDividedItem.Trim();
                string[] divideVerAndSign = trimmedExpDividedItem.Split(" ");
                versionAndSign.Add(Tuple.Create(divideVerAndSign[0], divideVerAndSign[1]));
            }
            return versionAndSign;
        }

        public static bool IsVersionsExp(string v1, string v2, string sign)
        {
            var version1 = new Version(v1);
            var version2 = new Version(v2);

            var compareVersions = version1.CompareTo(version2);

            if (sign.Equals("="))
            {
                return (compareVersions == 0);
            } else if (sign.Equals(">="))
            {
                return !(compareVersions < 0);
            } else if (sign.Equals("<="))
            {
                return !(compareVersions > 0);
            }
            // sign is less than
            return (compareVersions < 0);
        }
    }
}
