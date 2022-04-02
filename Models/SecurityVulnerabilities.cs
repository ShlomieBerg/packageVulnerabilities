namespace packageVulnerabilities.Models
{
    public class SecurityVulnerabilities
    {
        public enum SecurityAdvisorySeverity
        {
            CRITICAL,
            HIGH,
            LOW,
            MODERATE
        }
        public enum SecurityAdvisoryEcosystem
        {
            COMPOSER,
            GO,
            MAVEN,
            NPM,
            PIP,
            RUBYGEMS,
            RUST
        }
        public class SecurityAdvisoryPackageVersion
        {
            public String Identifier { get; set; }
        }
        public class SecurityAdvisoryPackage
        {
            public SecurityAdvisoryEcosystem EcoSystem { get; set; }
            public String Name { get; set; }
        }
        public class SecurityVulnerability
        {
            public SecurityAdvisoryPackageVersion FirstPatchedVersion { get; set; }
            public SecurityAdvisoryPackage Package { get; set; }
            public SecurityAdvisorySeverity Severity { get; set; }
            public String VulnerableVersionRange { get; set; }
        }

        public class SecurityVulnerabilityConnection
        {
            public List<SecurityVulnerability> Nodes { get; set; }
        }

        public class ResponseType
        {
            public SecurityVulnerabilityConnection SecurityVulnerabilities { get; set; }
        }
    }
}
