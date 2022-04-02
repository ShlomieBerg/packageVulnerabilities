# packageVulnerabilities
After pulling this project Create an .env file on your local machine and add GITHUB-ACCESS-TOKEN.

Scan endpoint supports only Github securityVulnerabilities GraphQL API at this moment.

In order to use this API:
1. Use swagger through https://localhost:7102/swagger

2. Use the API directly through Post Requst to https://localhost:5102

body example:
{
  "ecoSystem": "npm",
  "fileContentBase64": "ewoibmFtZSI6ICJteUFwcGxpY2F0aW9uIiwKInZlcnNpb24iOiAiMS4wLjAiLAoiZGVwZW5kZW5jaWVzIjogewoiZGVlcC1vdmVycmlkZSI6ICIxLjAuMSIsCiJleHByZXNzIjogIjQuMTcuMSIKfQp9"
}

* Currently the API only supports npm.