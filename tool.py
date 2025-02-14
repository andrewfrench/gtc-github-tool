import os
import jwt
import time
import requests
from base64 import b64decode
from attrs import define, field
from griptape.tools import BaseTool
from griptape.artifacts import TextArtifact
from schema import Schema, Literal, Optional
from griptape.utils.decorators import activity


@define
class GitHubIssueTool(BaseTool):
    github_api_base_url: str = field(default="https://api.github.com", kw_only=True)
    github_app_id: str = field(default=None, kw_only=True)
    github_installation_id: str = field(default=None, kw_only=True)
    github_private_key_b64: str = field(default=None, kw_only=True)

    def _generate_jwt(self):
        """ Generates a JWT for GitHub App authentication. """
        if not self.github_app_id or not self.github_private_key_b64:
            raise ValueError("GitHub App ID and private key path are required.")

        private_key = b64decode(self.github_private_key_b64)

        payload = {
            "iat": int(time.time()),
            "exp": int(time.time()) + (10 * 60),  # JWT valid for 10 minutes
            "iss": self.github_app_id
        }
        return jwt.encode(payload, private_key, algorithm="RS256")

    def _get_installation_token(self):
        """ Exchanges a JWT for an installation access token. """
        jwt_token = self._generate_jwt()
        url = f"{self.github_api_base_url}/app/installations/{self.github_installation_id}/access_tokens"

        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        response = requests.post(url, headers=headers)
        if response.status_code == 201:
            return response.json().get("token")
        raise ValueError(f"Failed to get installation token: {response.text}")

    def _get_headers(self):
        """ Returns headers with the installation token for API authentication. """
        installation_token = self._get_installation_token()
        return {"Authorization": f"Bearer {installation_token}", "Accept": "application/vnd.github.v3+json"}

    @activity(
        config={
            "description": "Opens a new issue on a specified GitHub repository.",
            "schema": Schema({
                Literal("owner", description="The owner of the repository."): str,
                Literal("repo", description="The name of the repository."): str,
                Literal("title", description="The title of the issue."): str,
                Optional("body", description="The body content of the issue."): str,
            }),
        }
    )
    def open_issue(self, values: dict) -> TextArtifact:
        """ Opens a new issue in the specified GitHub repository. """
        url = f"{self.github_api_base_url}/repos/{values['owner']}/{values['repo']}/issues"
        payload = {"title": values["title"], "body": values.get("body", "")}
        response = requests.post(url, json=payload, headers=self._get_headers())

        if response.status_code == 201:
            return TextArtifact(f"Issue created successfully: {response.json().get('html_url')}")
        return TextArtifact(f"Error creating issue: {response.text}")

    @activity(
        config={
            "description": "Closes an existing issue in a GitHub repository.",
            "schema": Schema({
                Literal("owner", description="The owner of the repository."): str,
                Literal("repo", description="The name of the repository."): str,
                Literal("issue_number", description="The number of the issue to close."): int,
            }),
        }
    )
    def close_issue(self, values: dict) -> TextArtifact:
        """ Closes an existing issue in the specified GitHub repository. """
        url = f"{self.github_api_base_url}/repos/{values['owner']}/{values['repo']}/issues/{values['issue_number']}"
        payload = {"state": "closed"}
        response = requests.patch(url, json=payload, headers=self._get_headers())

        if response.status_code == 200:
            return TextArtifact(f"Issue #{values['issue_number']} closed successfully.")
        return TextArtifact(f"Error closing issue: {response.text}")

    @activity(
        config={
            "description": "Edits an issue in a GitHub repository (e.g., change title, body, or state).",
            "schema": Schema({
                Literal("owner", description="The owner of the repository."): str,
                Literal("repo", description="The name of the repository."): str,
                Literal("issue_number", description="The number of the issue to edit."): int,
                Optional("title", description="New title for the issue."): str,
                Optional("body", description="New body content for the issue."): str,
                Optional("state", description="New state of the issue (open or closed)."): str,
            }),
        }
    )
    def edit_issue(self, values: dict) -> TextArtifact:
        """ Edits an existing issue (title, body, or state) in a GitHub repository. """
        url = f"{self.github_api_base_url}/repos/{values['owner']}/{values['repo']}/issues/{values['issue_number']}"
        payload = {key: value for key, value in values.items() if key in ["title", "body", "state"]}
        response = requests.patch(url, json=payload, headers=self._get_headers())

        if response.status_code == 200:
            return TextArtifact(f"Issue #{values['issue_number']} updated successfully.")
        return TextArtifact(f"Error updating issue: {response.text}")

    @activity(
        config={
            "description": "Lists issues in a GitHub repository with optional filters.",
            "schema": Schema({
                Literal("owner", description="The owner of the repository."): str,
                Literal("repo", description="The name of the repository."): str,
                Optional("state", description="Filter by issue state: open or closed. Default is all."): str,
                Optional("creator", description="Filter by issue creator."): str,
                Optional("assignee", description="Filter by assignee. 'none' for unassigned."): str,
                Optional("labels", description="Comma-separated labels (e.g., 'bug,urgent')."): str,
                Optional("limit", description="Number of issues to retrieve (default: 20)."): int,
            }),
        }
    )
    def list_issues(self, values: dict) -> TextArtifact:
        """ Searches issues in a GitHub repository with optional filters. """
        url = f"{self.github_api_base_url}/repos/{values['owner']}/{values['repo']}/issues"

        params = {
            "state": values.get("state", "all"),
            "creator": values.get("creator"),
            "assignee": values.get("assignee"),
            "labels": values.get("labels"),
            "per_page": values.get("limit", 20),
        }
        params = {k: v for k, v in params.items() if v}  # Remove None values

        response = requests.get(url, params=params, headers=self._get_headers())

        if response.status_code == 200:
            issues = response.json()
            if not issues:
                return TextArtifact("No matching issues found.")

            result = "\n".join(f"#{issue['number']}: {issue['title']} - {issue['state']}" for issue in issues)
            return TextArtifact(f"Found issues:\n{result}")
        return TextArtifact(f"Error searching issues: {response.text}")

    @activity(
        config={
            "description": "Retrieves details of a specific issue in a GitHub repository.",
            "schema": Schema({
                Literal("owner", description="The owner of the repository."): str,
                Literal("repo", description="The name of the repository."): str,
                Literal("issue_number", description="The number of the issue to retrieve."): int,
            }),
        }
    )
    def get_issue_details(self, values: dict) -> TextArtifact:
        """ Retrieves details about a specific GitHub issue. """
        url = f"{self.github_api_base_url}/repos/{values['owner']}/{values['repo']}/issues/{values['issue_number']}"
        response = requests.get(url, headers=self._get_headers())

        if response.status_code == 200:
            issue = response.json()
            details = (
                f"Issue #{issue['number']} - {issue['title']}\n"
                f"State: {issue['state']}\n"
                f"Created by: {issue['user']['login']}\n"
                f"Assignee: {issue['assignee']['login'] if issue['assignee'] else 'Unassigned'}\n"
                f"Created at: {issue['created_at']}\n"
                f"Updated at: {issue['updated_at']}\n"
                f"Closed at: {issue['closed_at'] if issue['closed_at'] else 'Still open'}\n"
                f"Labels: {', '.join(label['name'] for label in issue['labels'])}\n"
                f"Body: {issue['body'] if issue['body'] else 'No description provided.'}\n"
                f"URL: {issue['html_url']}"
            )
            return TextArtifact(details)
        return TextArtifact(f"Error retrieving issue details: {response.text}")

    @activity(
        config={
            "description": "Lists repositories accessible by the GitHub App installation.",
        }
    )
    def list_repositories(self, values: dict = None) -> TextArtifact:
        """ Lists repositories accessible by the GitHub App installation. """
        url = f"{self.github_api_base_url}/installation/repositories"
        response = requests.get(url, headers=self._get_headers())

        if response.status_code == 200:
            repos = response.json().get("repositories", [])
            if not repos:
                return TextArtifact("No repositories found.")

            repo_list = "\n".join([f"{repo['full_name']} (Private: {repo['private']})" for repo in repos])
            return TextArtifact(f"Repositories accessible by GitHub App:\n{repo_list}")
        return TextArtifact(f"Error listing repositories: {response.text}")

    @activity(
        config={
            "description": "Retrieves details of a specific GitHub repository.",
            "schema": Schema({
                Literal("owner", description="The owner of the repository."): str,
                Literal("repo", description="The name of the repository."): str,
            }),
        }
    )
    def get_repository_details(self, values: dict) -> TextArtifact:
        """ Retrieves details about a specific GitHub repository. """
        url = f"{self.github_api_base_url}/repos/{values['owner']}/{values['repo']}"
        response = requests.get(url, headers=self._get_headers())

        if response.status_code == 200:
            repo = response.json()
            details = (
                f"Repository: {repo['full_name']}\n"
                f"Description: {repo['description'] or 'No description provided.'}\n"
                f"Visibility: {'Private' if repo['private'] else 'Public'}\n"
                f"Default Branch: {repo['default_branch']}\n"
                f"Created at: {repo['created_at']}\n"
                f"Last Updated: {repo['updated_at']}\n"
                f"Stars: {repo['stargazers_count']}, Forks: {repo['forks_count']}, Open Issues: {repo['open_issues_count']}\n"
                f"URL: {repo['html_url']}"
            )
            return TextArtifact(details)
        return TextArtifact(f"Error retrieving repository details: {response.text}")

    @activity(
        config={
            "description": "Lists pull requests in a repository with optional filters.",
            "schema": Schema({
                Literal("owner", description="The owner of the repository."): str,
                Literal("repo", description="The name of the repository."): str,
                Optional("state", description="Filter by PR state: open, closed, or all. Default is open."): str,
                Optional("author", description="Filter by PR author."): str,
                Optional("base", description="Filter by base branch (e.g., 'main')."): str,
                Optional("limit", description="Number of PRs to retrieve (default: 20)."): int,
            }),
        }
    )
    def list_pull_requests(self, values: dict) -> TextArtifact:
        """ Lists pull requests in a GitHub repository with optional filters. """
        url = f"{self.github_api_base_url}/repos/{values['owner']}/{values['repo']}/pulls"

        params = {
            "state": values.get("state", "open"),
            "creator": values.get("author"),
            "base": values.get("base"),
            "per_page": values.get("limit", 20),
        }
        params = {k: v for k, v in params.items() if v}

        response = requests.get(url, params=params, headers=self._get_headers())

        if response.status_code == 200:
            prs = response.json()
            if not prs:
                return TextArtifact("No matching pull requests found.")

            result = "\n".join(f"#{pr['number']}: {pr['title']} - {pr['state']} (By {pr['user']['login']})" for pr in prs)
            return TextArtifact(f"Pull Requests:\n{result}")
        return TextArtifact(f"Error retrieving pull requests: {response.text}")

    @activity(
        config={
            "description": "Retrieves details of a specific pull request in a GitHub repository.",
            "schema": Schema({
                Literal("owner", description="The owner of the repository."): str,
                Literal("repo", description="The name of the repository."): str,
                Literal("pr_number", description="The number of the pull request to retrieve."): int,
            }),
        }
    )
    def get_pull_request_details(self, values: dict) -> TextArtifact:
        """ Retrieves details about a specific pull request. """
        url = f"{self.github_api_base_url}/repos/{values['owner']}/{values['repo']}/pulls/{values['pr_number']}"
        response = requests.get(url, headers=self._get_headers())

        if response.status_code == 200:
            pr = response.json()
            details = (
                f"Pull Request #{pr['number']} - {pr['title']}\n"
                f"State: {pr['state']}\n"
                f"Created by: {pr['user']['login']}\n"
                f"Base Branch: {pr['base']['ref']}, Head Branch: {pr['head']['ref']}\n"
                f"Created at: {pr['created_at']}\n"
                f"Updated at: {pr['updated_at']}\n"
                f"Merged: {'Yes' if pr['merged_at'] else 'No'}\n"
                f"Body: {pr['body'] if pr['body'] else 'No description provided.'}\n"
                f"URL: {pr['html_url']}"
            )
            return TextArtifact(details)
        return TextArtifact(f"Error retrieving PR details: {response.text}")


def init_tool() -> GitHubIssueTool:
    github_app_id = os.environ.get("GITHUB_APP_ID")
    github_installation_id = os.environ.get("GITHUB_INSTALLATION_ID")
    github_private_key_b64 = os.environ.get("GITHUB_PRIVATE_KEY_B64")

    if not github_app_id or not github_installation_id or not github_private_key_b64:
        raise ValueError("GitHub App ID, installation ID, and private key are required.")

    return GitHubIssueTool(
        github_app_id=github_app_id,
        github_installation_id=github_installation_id,
        github_private_key_b64=github_private_key_b64,
    )
