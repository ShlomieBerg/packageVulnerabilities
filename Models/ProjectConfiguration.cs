using System.ComponentModel.DataAnnotations;

namespace packageVulnerabilities.Models
{
    public class ProjectConfiguration
    {
        [Required]
        public string EcoSystem { get; set; } = string.Empty;
        [Required]
        public string FileContentBase64 { get; set; } = string.Empty;
    }
}
