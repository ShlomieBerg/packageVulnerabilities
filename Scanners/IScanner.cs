namespace packageVulnerabilities.Scanners
{
    public interface IScanner
    {
        bool IsEcoSystemValid(string ecoSystem);
        async Task<string> ScanFileContent(string content, string ecoSystem);
    }
}
