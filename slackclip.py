"""Copy the contents of a Slack thread.

slackclip uses your personal Slack credentials to extract the content of a
thread from Slack, allowing you to store it elsewhere.

Original author: Heath Raftery <heath@empirical.ee>
"""

import argparse
import os
import pathlib
import pickle
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse

import emoji
import requests
from pyperclip import copy

LOCAL_STORE_PATH = pathlib.Path("~/.config/slackclip/").expanduser()
CREDENTIALS_FILE = LOCAL_STORE_PATH / "credentials"


class InvalidCredentialsError(Exception):
    """Raised when Slack API returns invalid_auth error."""


class SlackClient:
    """Handles Slack API calls with credential caching."""

    def __init__(self, token: str, cookie: dict):
        self.token = token
        self.cookie = cookie
        self._display_name_cache: dict[str, str] = {}

    def get_messages(self, channel: str, timestamp: str) -> list[dict]:
        """Query the Slack API for messages in a thread.

        Args:
            channel: Channel ID
            timestamp: Thread timestamp

        Returns:
            List of message dicts from the API

        Raises:
            InvalidCredentialsError: Credentials are invalid or expired
            RuntimeError: Failed to query the Slack API
        """
        query = urlencode(
            {"token": self.token, "channel": channel, "ts": timestamp},
            quote_via=lambda s, *_: s,
        )

        try:
            response = requests.get(
                "https://slack.com/api/conversations.replies",
                params=query,
                cookies={self.cookie["name"]: self.cookie["value"]},
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to query Slack API: {e}") from e

        if not data.get("ok"):
            error = data.get("error", "unknown")
            if error == "invalid_auth":
                raise InvalidCredentialsError("Slack credentials are invalid or expired.")
            raise RuntimeError(f"Slack API returned error: {error}")

        return data["messages"]

    def get_display_name(self, user_id: str) -> str:
        """Get the display name for a user, with caching.

        Args:
            user_id: Slack user ID

        Returns:
            Display name or real name

        Raises:
            RuntimeError: Failed to query the Slack API
        """
        if user_id in self._display_name_cache:
            return self._display_name_cache[user_id]

        query = urlencode(
            {"token": self.token, "user": user_id},
            quote_via=lambda s, *_: s,
        )

        try:
            response = requests.get(
                "https://slack.com/api/users.info",
                params=query,
                cookies={self.cookie["name"]: self.cookie["value"]},
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to query Slack API: {e}") from e

        if not data.get("ok"):
            error = data.get("error", "unknown")
            if error == "invalid_auth":
                raise InvalidCredentialsError("Slack credentials are invalid or expired.")
            raise RuntimeError(f"Slack API returned error: {error}")

        profile = data["user"]["profile"]
        name = profile.get("display_name") or profile.get("real_name", "Unknown")
        self._display_name_cache[user_id] = name
        return name


def prompt_for_credentials(workspace_url: str, expired: bool = False) -> tuple[str, dict]:
    """Prompt the user to enter their Slack credentials interactively.

    Args:
        workspace_url: The workspace URL (e.g., "https://mycompany.slack.com/")
        expired: If True, shows "expired" message instead of "not found"

    Returns:
        Tuple of (token, cookie_dict)
    """
    workspace_name = (
        workspace_url.split("//")[1].split(".")[0] if "//" in workspace_url else "workspace"
    )

    print()
    if expired:
        print(f"Credentials expired or invalid for {workspace_name}.slack.com")
    else:
        print(f"No credentials found for {workspace_name}.slack.com")
    print()
    print("To get your credentials from the browser:")
    print("1. Open Slack in your browser and log in")
    print("2. Open Developer Tools (F12 or Cmd+Option+I)")
    print("3. Go to Console tab and run: JSON.parse(localStorage.localConfig_v2).teams")
    print("4. Find your workspace and copy the 'token' value (starts with 'xoxc-')")
    print()

    token = input("Enter your xoxc- token: ").strip()
    if not token.startswith("xoxc-"):
        print("Warning: Token does not start with 'xoxc-'. It may not work.")

    print()
    print("5. Go to Application tab -> Cookies -> https://app.slack.com")
    print("6. Find the cookie named 'd' and copy its value")
    print()

    cookie_value = input("Enter your 'd' cookie value: ").strip()

    return token, {"name": "d", "value": cookie_value}


def save_credentials(workspace_url: str, token: str, cookie: dict) -> None:
    """Save credentials for a workspace to the local store.

    Args:
        workspace_url: The workspace URL
        token: The xoxc- token
        cookie: The cookie dict with 'name' and 'value' keys

    Raises:
        OSError: Failed to persist to file
    """
    workspace_name = (
        workspace_url.split("//")[1].split(".")[0] if "//" in workspace_url else "workspace"
    )

    try:
        creds = get_credentials_from_store()
    except (FileNotFoundError, pickle.UnpicklingError):
        creds = {"tokens": {}, "cookie": None}

    creds["tokens"][workspace_url] = {"token": token, "name": workspace_name}
    creds["cookie"] = cookie

    try:
        os.makedirs(LOCAL_STORE_PATH, exist_ok=True)
        with open(CREDENTIALS_FILE, "wb") as f:
            pickle.dump(creds, f)
    except Exception as e:
        raise OSError("Unable to persist credentials to file.") from e


def get_credentials_from_store() -> dict:
    """Read credentials from the local store.

    Returns:
        Credentials dict with 'tokens' and 'cookie' keys

    Raises:
        FileNotFoundError: Credentials file doesn't exist
    """
    with open(CREDENTIALS_FILE, "rb") as f:
        return pickle.load(f)


def get_token_and_cookie_for_workspace(url: str) -> tuple[str, dict]:
    """Get the token and cookie for the specified workspace.

    Args:
        url: Workspace URL (e.g., "https://my-workspace.slack.com/")

    Returns:
        Tuple of (token, cookie_dict)

    Raises:
        KeyError: No token found for the workspace
        FileNotFoundError: Credentials file doesn't exist
    """
    creds = get_credentials_from_store()
    if url not in creds["tokens"]:
        raise KeyError(f"No token found matching the workspace URL: {url}")
    return creds["tokens"][url]["token"], creds["cookie"]


def parse_slack_message_link(link: str) -> tuple[str, str, str]:
    """Extract workspace URL, channel ID, and timestamp from a Slack message link.

    Slack "Copy link" URLs are formatted as:
        https://<workspace>.slack.com/archives/<channel_id>/p<timestamp_microseconds>

    Args:
        link: Slack message link

    Returns:
        Tuple of (workspace_url, channel_id, timestamp)

    Raises:
        ValueError: Unable to parse the link
    """
    link_display = link.replace("%", "")
    error_prefix = f'Unexpected link format: Got "{link_display[:100]}"'

    try:
        parsed = urlparse(link)
        parts = parsed.path.strip("/").split("/")
        if len(parts) != 3:
            raise ValueError(f"{error_prefix} - expected 3 path parts")
        archives, channel_id, ts_part = parts
    except Exception as e:
        raise ValueError(f"{error_prefix} - could not parse as URL") from e

    if not parsed.scheme:
        raise ValueError(f'{error_prefix} - link must include a scheme (e.g., "https")')
    if archives != "archives":
        raise ValueError(f'{error_prefix} - first path part must be "archives"')
    if not ts_part.startswith("p"):
        raise ValueError(f"{error_prefix} - timestamp must start with 'p'")
    if not ts_part[1:].isnumeric():
        raise ValueError(f"{error_prefix} - timestamp after 'p' must be numeric")
    if len(ts_part) != 17:  # 'p' + 10 digits + 6 digits
        raise ValueError(f"{error_prefix} - timestamp must be 16 digits")

    workspace_url = f"{parsed.scheme}://{parsed.netloc}/"
    timestamp = f"{ts_part[1:11]}.{ts_part[11:17]}"

    return workspace_url, channel_id, timestamp


def slack_ts_to_datetime_str(ts_str: str) -> str:
    """Convert a Slack timestamp to human-readable datetime string.

    Slack timestamps are formatted as "<unix_time>.<sequence_number>".

    Args:
        ts_str: Slack timestamp string

    Returns:
        Datetime string in "YYYY-MM-DD HH:MM:SS" format
    """
    unix_time = int(ts_str.partition(".")[0])
    return datetime.fromtimestamp(unix_time, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def slack_text_to_markdown(text: str, client: SlackClient) -> str:
    """Convert Slack mrkdwn format to standard Markdown.

    Slack's mrkdwn format differs from Markdown:
    - Bold: *text* (single asterisk)
    - Italic: _text_ (single underscore)
    - URLs: <url|text>
    - Mentions: <@user_id>
    - Channels: <#channel_id>
    - Emoji: :name:
    - Escapes: &amp; &lt; &gt;

    Args:
        text: Slack mrkdwn text
        client: SlackClient for resolving user mentions

    Returns:
        Standard Markdown text
    """

    def mention_to_name(match: re.Match) -> str:
        user_id = match.group(1)
        try:
            name = client.get_display_name(user_id)
            return f"[@{name}]"
        except RuntimeError:
            return f"[@{user_id}]"

    def asterisk_to_bold(match: re.Match) -> str:
        # Preserve asterisks inside code blocks
        if match.group(0).startswith("`") and match.group(0).endswith("`"):
            return match.group(0)
        return "**"

    # Convert mrkdwn to markdown
    text = re.sub(r"`.*?`|\*", asterisk_to_bold, text)  # Bold (preserve code)
    text = re.sub(r"<#(.*?)>", r"[#\1]", text)  # Channel links
    text = re.sub(r"<@(.*?)>", mention_to_name, text)  # Mentions
    text = re.sub(r"<(.*?)\|(.*?)>", r"[\2](\1)", text)  # URLs
    text = emoji.emojize(text, language="alias")  # Emoji
    text = text.replace("&amp;", "&")  # Unescape &
    text = text.replace("&lt;", "<")  # Unescape <
    text = text.replace("&gt;", ">")  # Unescape >

    return text


def get_thread_content(link: str) -> str:
    """Get the content of a Slack thread as Markdown.

    Prompts for credentials interactively if not found or expired.

    Args:
        link: Slack message link

    Returns:
        Thread content as Markdown

    Raises:
        RuntimeError: Failed to query the Slack API
        ValueError: Unable to parse the link
    """
    workspace, channel, timestamp = parse_slack_message_link(link)

    # Get or prompt for credentials
    try:
        token, cookie = get_token_and_cookie_for_workspace(workspace)
    except (KeyError, FileNotFoundError):
        token, cookie = prompt_for_credentials(workspace)
        save_credentials(workspace, token, cookie)
        print()
        print("Credentials saved!")
        print()

    client = SlackClient(token, cookie)

    # Fetch messages, retrying once if credentials are invalid
    try:
        messages = client.get_messages(channel, timestamp)
    except InvalidCredentialsError:
        token, cookie = prompt_for_credentials(workspace, expired=True)
        save_credentials(workspace, token, cookie)
        print()
        print("Credentials saved!")
        print()
        client = SlackClient(token, cookie)
        messages = client.get_messages(channel, timestamp)

    # Format messages as Markdown
    output = []
    for msg in messages:
        name = client.get_display_name(msg["user"])
        time = slack_ts_to_datetime_str(msg["ts"])
        text = slack_text_to_markdown(msg["text"], client)
        output.append(f"**{name or 'Anonymous'}, at {time}:**\n{text}\n")

    return "\n".join(output)


def is_valid_slack_url(link: str) -> bool:
    """Check if a string looks like a valid Slack URL."""
    try:
        parsed = urlparse(link)
        return bool(parsed.scheme and parsed.netloc and "slack" in parsed.netloc.lower())
    except Exception:
        return False


def print_err(*args, **kwargs):
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def generate_output_filename() -> str:
    """Generate a filename based on current timestamp."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"slack-thread-{ts}.md"


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Note: this program is not endorsed or authorized in any way by Slack Technologies LLC.",
        description="Extract the contents of a Slack thread.",
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="Slack thread URL (required unless using --pipe)",
    )
    parser.add_argument(
        "-p",
        "--pipe",
        action="store_true",
        help="read URL from stdin, write content to stdout",
    )
    parser.add_argument(
        "-f",
        "--file",
        nargs="?",
        const=True,
        metavar="PATH",
        help="save to file instead of clipboard; without PATH, auto-generates filename",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="show stack trace on error",
    )

    args = parser.parse_args()

    try:
        # Get the URL from arg or stdin
        if args.url:
            link = args.url
        elif args.pipe:
            link = sys.stdin.read().strip()
        else:
            parser.error("URL is required (or use --pipe to read from stdin)")

        # Validate the URL
        if not is_valid_slack_url(link):
            raise ValueError(f"Invalid Slack URL: {link[:200]}")

        if not args.pipe:
            print(f"Fetching thread: {link[:100]}...")

        content = get_thread_content(link)

        # Output: stdout, file, or clipboard
        if args.pipe:
            print(content)
        elif args.file:
            filename = args.file if isinstance(args.file, str) else generate_output_filename()
            with open(filename, "w") as f:
                f.write(content)
            print(f"Saved to {filename}")
        else:
            copy(content)
            print("Done. Content copied to clipboard.")

    except Exception as e:
        print_err("Failed. Details of error are below.")
        if args.debug:
            raise
        print_err(f"--> {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
