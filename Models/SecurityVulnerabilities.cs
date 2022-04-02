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

        public class PackageVulnerability
        {
            public PackageVulnerability(PackageVulnerability previousPackageVulnerability)
            {
                Name = previousPackageVulnerability.Name;
                Version = previousPackageVulnerability.Version;
                Severity = previousPackageVulnerability.Severity;
                FirstPatchedVersion = previousPackageVulnerability.FirstPatchedVersion;
            }
            public PackageVulnerability(String name, String version, String severity, String firstPatchedVersion)
            {
                Name = name;
                Version = version;
                Severity = severity;
                FirstPatchedVersion = firstPatchedVersion;
            }
            public String Name { get; set; }
            public String Version { get; set; }
            public String Severity { get; set; }
            public String FirstPatchedVersion { get; set; }
        }

        public class PackagesVulnerability
        {
            public PackagesVulnerability(PackagesVulnerability previousPackagesVulnerability)
            {
                VulnerablePackges = new List<PackageVulnerability>();
                previousPackagesVulnerability.VulnerablePackges
                    .ForEach(prevPackageVulnerability => VulnerablePackges.Add(new PackageVulnerability(prevPackageVulnerability)));
            }
            public PackagesVulnerability()
            {
                VulnerablePackges = new List<PackageVulnerability>();
            }
            public List<PackageVulnerability> VulnerablePackges { get; set; }
        }
    }
}                 
