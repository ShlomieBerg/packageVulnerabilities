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
    }
}
