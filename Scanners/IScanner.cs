using static packageVulnerabilities.Models.SecurityVulnerabilities;

namespace packageVulnerabilities.Scanners
{
    public interface IScanner
    {
        bool IsEcoSystemValid(string ecoSystem);
        Task<PackagesVulnerability> ScanFileContent(string content, string ecoSystem); //overRide for different responses
    }
}
