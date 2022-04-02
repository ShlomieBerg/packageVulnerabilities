using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using packageVulnerabilities.Scanners;
using static packageVulnerabilities.Models.SecurityVulnerabilities;

namespace packageVulnerabilities.Controllers
{
    [Route("api/v1/scan")]
    [ApiController]
    public class ScanController : ControllerBase
    {
        [HttpPost]
        public async Task<ActionResult<PackagesVulnerability>> ScanForVulnerabilities([FromBody] Models.ProjectConfiguration input)
        {
            // one way to extend code is to support routes that except the platform in the route itself e.g /scan/github,
            // and to get the appropriate scanner before executing the code.
            GithubScanner scanner = GithubScanner.GetInstance;
            //TODO: find a way to show supported eco systems

            bool isValid = scanner.IsEcoSystemValid(input.EcoSystem);
            // validate input here
             
            if (!isValid)
                throw new ArgumentException($"Eco System \"{input.EcoSystem}\" is not supported.");
            PackagesVulnerability res = new PackagesVulnerability(await scanner.ScanFileContent(input.FileContentBase64, input.EcoSystem));
            if (false)
                return BadRequest();
            return Ok(res);
        }
    }
}
