namespace packageVulnerabilities.Scanners
{
    public interface IScanner
    {
        bool IsEcoSystemValid(string ecoSystem);
        Task<string> ScanFileContent(string content, string ecoSystem);
    }
}
