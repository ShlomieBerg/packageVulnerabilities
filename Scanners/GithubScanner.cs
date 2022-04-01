using GraphQL.Client.Http;
using GraphQL.Client.Serializer.Newtonsoft;
using GraphQL;
using Newtonsoft.Json.Linq;

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

            // TODO should move to helper util
            byte[] encodedDataAsBytes = System.Convert.FromBase64String(content);
            string decodedContentFromBase64 = System.Text.ASCIIEncoding.ASCII.GetString(encodedDataAsBytes);
            
            // should use try catch here
            JObject obj = JObject.Parse(decodedContentFromBase64);

            JEnumerable<JToken> dependencies = obj.GetValue("dependencies").Children();

            IEnumerator<JToken> dependenciesEnumerator = dependencies.GetEnumerator();
            while (dependenciesEnumerator.MoveNext())
            {
                JToken dependency = dependenciesEnumerator.Current;
                // dependecy = "deep-override": "1.0.1" - for each token figure out how to send the key to api and the compare with version



            }
            var request = new GraphQLRequest
            {
               Query = @"query securityVulnerabilities ($ecoSystem: SecurityAdvisoryEcosystem, $first: Int, $package: String) { securityVulnerabilities (ecoSystem: $ecoSystem, first: $first, package: $package) { nodes { severity, package {name, ecosystem}, vulnerableVersionRange, firstPatchedVersion { identifier } } } }",
               OperationName = "securityVulnerabilities",
               Variables = new
               {
                   ecoSystem = ecoSystem.ToUpper(),
                   first = 100,
                   package = "deep-override"
               }
            };

            /*try
            {
                var graphQLResponse = await graphQLHttpClient.SendQueryAsync<dynamic>(request);
            } catch (Exception ex)
            {
            }*/
            return "Ok";
        }
    }
}
