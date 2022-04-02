using GraphQL.Client.Http;
using GraphQL.Client.Serializer.Newtonsoft;
using GraphQL;
using Newtonsoft.Json.Linq;
using static packageVulnerabilities.Models.SecurityVulnerabilities;
using packageVulnerabilities.Utils;

namespace packageVulnerabilities.Scanners
{
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
        public async Task<PackagesVulnerability> ScanFileContent(string content, string ecoSystem)
        {
            PackagesVulnerability vulenrabilities = new PackagesVulnerability();
            string jsonToString = Helper.FromBase64(content);

            JObject obj = JObject.Parse(jsonToString);

            JEnumerable<JToken> dependencies = obj.GetValue("dependencies").Children();


            foreach (JToken item in dependencies)
            {
                // dependecy = "deep-override": "1.0.1" - for each token figure out how to send the key to api and the compare with version


                String package = item.Path.Substring(Consts.RemoveDependenciesIdx);
                String currVersion = item.First.ToString();

                var request = new GraphQLRequest
                {
                    Query = @"query securityVulnerabilities ($ecosystem: SecurityAdvisoryEcosystem, $first: Int, $package: String) { securityVulnerabilities (ecosystem: $ecosystem, first: $first, package: $package) { nodes { severity, package {name, ecosystem}, vulnerableVersionRange, firstPatchedVersion { identifier } } } }",
                    OperationName = "securityVulnerabilities",
                    Variables = new
                    {
                        ecosystem = Helper.GetEcoSystemEnumValue(ecoSystem),
                        first = 100,
                        package
                    }
                };
                var response = await graphQLHttpClient.SendQueryAsync<ResponseType>(request);

                List<SecurityVulnerability> nodes = response.Data.SecurityVulnerabilities.Nodes;
                // go over all the response nodes
                foreach (var node in nodes)
                {

                    List<Tuple<string, string>> seperatedSignAndVersion = Helper.GetVersionsAndSigns(node.VulnerableVersionRange);
                    // check if curr version in in the vulnerable version range
                    bool isVulnerable = seperatedSignAndVersion.All(tuple => Helper.IsVersionsExp(currVersion, tuple.Item2, tuple.Item1));

                    if (isVulnerable)
                    {
                        vulenrabilities.VulnerablePackges.Add(new PackageVulnerability(package, currVersion, node.Severity.ToString(), node.FirstPatchedVersion.Identifier));
        
                    }
                }
            };
            return vulenrabilities;
        }
    }
}
