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

            bool isEcoSystemValid = scanner.IsEcoSystemValid(input.EcoSystem);
           
            if (!isEcoSystemValid)
                return BadRequest($"EcoSystem \"{input.EcoSystem}\" is not supported.");
            try
            {
                PackagesVulnerability res = new PackagesVulnerability(await scanner.ScanFileContent(input.FileContentBase64, input.EcoSystem));
                return Ok(res);
            } catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
         
        }
    }
}
