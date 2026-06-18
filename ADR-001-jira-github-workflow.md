# ADR-001: Jira Issue Creation and GitHub/Jira Workflow

## Status
Accepted

## Context
In the Hermes webagency, we need to establish a standardized workflow for creating Jira issues and linking them to GitHub activities (branches, commits, pull requests). During initial testing of the workflow, we encountered technical challenges with the Jira CLI tool and learned specific requirements for the Jira REST API.

## Decision
We will use the Jira REST API v3 directly for issue creation and updates, rather than relying solely on the Jira CLI tool, due to compatibility issues with the CLI tool's endpoint usage. For issue descriptions and comments, we will use Atlassian Document Format (ADF) JSON structure as required by the Jira REST API v3.

Specifically:
1. For creating issues: Use `POST /rest/api/3/issue` with ADF-formatted description
2. For adding comments: Use `POST /rest/api/3/issue/{issueIdOrKey}/comment` with ADF-formatted body
3. For branching: Use the format `feature/JIRA-XXX-descriptive-name`, `bugfix/JIRA-XXX-descriptive-name`, etc.
4. For commits: Use the format `JIRA-XXX: description` (imperative mood, max 72 characters)
5. For pull requests: Reference the Jira issue in the title and description, and check the "Resolves JIRA-XXX" box in the GitHub UI
6. For workflow automation: Update Jira issue status based on GitHub activity (e.g., move to "In Progress" when branch is created, to "Code Review" when PR is opened, to "Testing" when PR is merged)

## Consequences
### Positive
- Reliable integration with Jira Cloud API
- Proper formatting of rich text content (description, comments)
- Clear traceability between Jira issues and GitHub activities
- Standardized workflow that can be automated
- Compliance with established webagency conventions

### Negative
- Requires handling ADF JSON structure which is more complex than plain text
- Slightly more complex implementation than using plain text (though still straightforward)
- Dependence on direct API usage rather than a CLI tool (but more reliable)

## Implementation Notes
When creating issues via the REST API:
- The `description` field must be an ADF document object, not a plain string
- Minimal ADF structure for a simple paragraph:
  ```json
  {
    "type": "doc",
    "version": 1,
    "content": [
      {
        "type": "paragraph",
        "content": [
          {
            "type": "text",
            "text": "Your plain text content here"
          }
        ]
      }
    ]
  }
  ```
- For issue creation, required fields are: `project.key`, `summary`, `description` (ADF), `issuetype.name` or `issuetype.id`
- Authentication is done via Basic Auth with email as username and API token as password

## Related Decisions
- None yet, as this is the first ADR.

## Notes
This decision was made during initial testing of the Jira/GitHub integration in the test-honeypot workspace, where we successfully:
1. Created Jira issue SCRUM-6 using the REST API with ADF formatting
2. Created a feature branch following the naming convention
3. Made commits with proper Jira-XXX: format
4. Created a pull request referencing the Jira issue
5. Updated the Jira issue with a comment containing the PR link
