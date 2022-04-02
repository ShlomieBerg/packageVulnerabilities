using GraphQL.Client.Http;
using GraphQL.Client.Serializer.Newtonsoft;
using GraphQL;
using Newtonsoft.Json.Linq;
using static packageVulnerabilities.Models.SecurityVulnerabilities;

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
        public async Task<string> ScanFileContent(string content, string ecoSystem)
        {
            var responseList = new List<dynamic>();
            string jsonToString = Utils.Helper.FromBase64(content);

            // should use try catch here
            JObject obj = JObject.Parse(jsonToString);

            JEnumerable<JToken> dependencies = obj.GetValue("dependencies").Children();


            foreach (JToken item in dependencies)
            {
                // dependecy = "deep-override": "1.0.1" - for each token figure out how to send the key to api and the compare with version

                String package = item.Path.Substring(Utils.Consts.RemoveDependenciesIdx);
                String currVersion = item.First.ToString();

                var request = new GraphQLRequest
                {
                    Query = @"query securityVulnerabilities ($ecosystem: SecurityAdvisoryEcosystem, $first: Int, $package: String) { securityVulnerabilities (ecosystem: $ecosystem, first: $first, package: $package) { nodes { severity, package {name, ecosystem}, vulnerableVersionRange, firstPatchedVersion { identifier } } } }",
                    OperationName = "securityVulnerabilities",
                    Variables = new
                    {
                        ecosystem = SecurityAdvisoryEcosystem.NPM,
                        first = 100,
                        package
                    }
                };// TODO use the variable to get enum NPM
                var response = graphQLHttpClient.SendQueryAsync<ResponseType>(request);

                List<SecurityVulnerability> nodes = response.Data.SecurityVulnerabilities.Nodes;

                foreach (var node in nodes)
                {
                    // for each node compare vulnerableVersionRange with currVersion,
                    // if true add to list new obj item with
                    // package's name
                    // affected version
                    // vulnerabilitiy's severity
                    // first patched version
                }


            };
            // add to graphql folder



            return "Ok";
        }
    }
}
