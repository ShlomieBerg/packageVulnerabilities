namespace packageVulnerabilities.Models
{
    public interface IScanner
    {
        bool IsEcoSystemValid(string ecoSystem);
        string ScanFileContent(string content);
    }
}
