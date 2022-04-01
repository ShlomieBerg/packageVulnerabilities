using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace packageVulnerabilities.Controllers
{
    [Route("api/v1/scan")]
    [ApiController]
    public class ScanController : ControllerBase
    {
        [HttpPost]
        public ActionResult ScanForVulnerabilities([FromBody] Models.ProjectConfiguration input)
        {
            bool failedRequest = false;
            bool throwException = false;
            if (throwException)
                throw new ArgumentException("bad ecosystem");
            if (failedRequest)
                return BadRequest();
            return Ok(input);
        }
    }
}
