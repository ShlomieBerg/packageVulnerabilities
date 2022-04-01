﻿using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using packageVulnerabilities.Scanners;

namespace packageVulnerabilities.Controllers
{
    [Route("api/v1/scan")]
    [ApiController]
    public class ScanController : ControllerBase
    {
        [HttpPost]
        public ActionResult ScanForVulnerabilities([FromBody] Models.ProjectConfiguration input)
        {
            // one way to extend code is to support routes that except the platform in the route itself e.g /scan/github,
            // and to get the appropriate scanner before executing the code.
            GithubScanner scanner = GithubScanner.GetInstance;
            //TODO: find a way to show supported eco systems

            bool isValid = scanner.IsEcoSystemValid(input.EcoSystem);
            if (!isValid)
                throw new ArgumentException($"Eco System \"{input.EcoSystem}\" is not supported.");
            
            if (false)
                return BadRequest();
            return Ok(isValid);
        }
    }
}
