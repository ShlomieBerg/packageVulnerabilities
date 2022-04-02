using GraphQL.Client.Http;
using GraphQL.Client.Serializer.Newtonsoft;
using GraphQL;
using Newtonsoft.Json.Linq;

namespace packageVulnerabilities.Scanners
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
        public String identifier { get; set; }
    }
    public class SecurityAdvisoryPackage
    {
        public SecurityAdvisoryEcosystem ecosystem { get; set; }
        public String name { get; set; }
    }
    public class SecurityVulnerability
    {
        public SecurityAdvisoryPackageVersion firstPatchedVersion { get; set; }
        public SecurityAdvisoryPackage package { get; set; }
        public SecurityAdvisorySeverity severity { get; set; }
        public String vulnerableVersionRange { get; set; }
    }

    public class SecurityVulnerabilityConnection
    {
        public List<SecurityVulnerability> nodes { get; set; }
    }

    public class ResponseVulnerabilityCollectionType
    {
        public List<SecurityVulnerabilityConnection> Vulnerabilities { get; set; }
    }
    public class ResponseVulnerabilitiyType
    {
        public SecurityVulnerabilityConnection SecurityVulnerabilityConnection { get; set; }
    }
    public sealed class GithubScanner : IScanner
    {
        private static GithubScanner instance = null;
        private string[] SupportedEcoSystems = new string[1] { "npm" };
        private static GraphQLHttpClient graphQLHttpClient;

        private GithubScanner()
        {
            var graphQLOptions = new GraphQLHttpClientOptions
            {
                EndPoint = new Uri("https://api.github.com/graphql"),

            };

            graphQLHttpClient = new GraphQLHttpClient(graphQLOptions, new NewtonsoftJsonSerializer());

            var token = Environment.GetEnvironmentVariable("GITHUB-ACCESS-TOKEN");
            graphQLHttpClient.HttpClient.DefaultRequestHeaders.Add("Authorization", "bearer " + token);
        }

        public static GithubScanner GetInstance
        {
            get
            {
                if (instance == null)
                    instance = new GithubScanner();
                return instance;
            }
        }
        public bool IsEcoSystemValid(string ecoSystem)
        {
            return SupportedEcoSystems.Contains(ecoSystem);
        }
        public async Task<string> ScanFileContent(string content, string ecoSystem)
        {

            string jsonToString = Utils.Helper.FromBase64(content);

            // should use try catch here
            JObject obj = JObject.Parse(jsonToString);

            JEnumerable<JToken> dependencies = obj.GetValue("dependencies").Children();            
       

            var tasks = dependencies.Select(async (item, idx) =>
            {
                // dependecy = "deep-override": "1.0.1" - for each token figure out how to send the key to api and the compare with version

                String package = item.Path.Substring(Utils.Consts.RemoveDependenciesIdx);
                String currVersion = item.First.ToString();

                // ecoSystem npm should have ENUM.
                var request = new GraphQLRequest
                {
                    Query = @"query securityVulnerabilities ($ecoSystem: SecurityAdvisoryEcosystem, $first: Int, $package: String) { securityVulnerabilities (ecoSystem: $ecoSystem, first: $first, package: $package) { nodes { severity, package {name, ecosystem}, vulnerableVersionRange, firstPatchedVersion { identifier } } } }",
                    OperationName = "securityVulnerabilities",
                    Variables = new
                    {
                        ecoSystem = ecoSystem.ToUpper(),
                        first = 100,
                        package
                    }
                };
                return graphQLHttpClient.SendQueryAsync<ResponseVulnerabilityCollectionType>(request);

            });

            foreach (var response in await Task.WhenAll(tasks))
            {
                Console.WriteLine(response);
            }


            /*while (dependenciesEnumerator.MoveNext())
            {
                JToken dependency = dependenciesEnumerator.Current;
                // dependecy = "deep-override": "1.0.1" - for each token figure out how to send the key to api and the compare with version
                String package = dependency.Path.Substring(Utils.Consts.RemoveDependenciesIdx);
                String currVersion = dependency.First.ToString();


                // ecoSystem npm should have ENUM.
                var request = new GraphQLRequest
                {
                    Query = @"query securityVulnerabilities ($ecoSystem: SecurityAdvisoryEcosystem, $first: Int, $package: String) { securityVulnerabilities (ecoSystem: $ecoSystem, first: $first, package: $package) { nodes { severity, package {name, ecosystem}, vulnerableVersionRange, firstPatchedVersion { identifier } } } }",
                    OperationName = "securityVulnerabilities",
                    Variables = new
                    {
                        ecoSystem = ecoSystem.ToUpper(),
                        first = 100,
                        package
                    }
                };

                try
                {
                    var graphQLResponse = await graphQLHttpClient.SendQueryAsync<dynamic>(request);
                    Console.WriteLine(graphQLResponse);

                }
                catch (Exception ex)
                {
                }


            }*/
            // add to graphql folder



            return "Ok";
        }
    }
}
