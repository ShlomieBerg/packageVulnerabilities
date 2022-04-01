namespace packageVulnerabilities.Models
{
    public class GithubScanner : IScanner
    {
        private string[] SupportedEcoSystems = new string[1] { "npm" };
        public bool IsEcoSystemValid(string ecoSystem)
        {
            return SupportedEcoSystems.Contains(ecoSystem);
        }
        public string ScanFileContent(string content)
        {
            return "";
        }
    }
}
