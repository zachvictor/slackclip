# slackclip

Copy the contents of a Slack thread.

---

## Description

`slackclip` extracts a Slack thread, formats it as Markdown, and copies it to the clipboard.

**This project is not endorsed or authorized in any way by Slack Technologies LLC.**

## Installation

Requires Python 3.10+.

```bash
pip install slackclip
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv pip install slackclip
```

## Usage

```bash
slackclip <slack-thread-url>
```

By default, output is copied to the clipboard.

### Save to file

```bash
# Auto-generate filename (slack-thread-YYYYMMDD-HHMMSS.md)
slackclip <url> -f

# Specify filename
slackclip <url> -f output.md
```

### Pipe mode

Read URL from stdin, write content to stdout:

```bash
echo "<url>" | slackclip -p
```

## First-time setup

On first run, `slackclip` will prompt you for your Slack credentials:

1. Open Slack in your browser and log in
2. Open Developer Tools (F12 or Cmd+Option+I)
3. Go to **Console** tab and run:
   ```javascript
   JSON.parse(localStorage.localConfig_v2).teams
   ```
4. Find your workspace and copy the `token` value (starts with `xoxc-`)
5. Go to **Application** tab → **Cookies** → `https://app.slack.com`
6. Find the cookie named `d` and copy its value

Credentials are saved to `~/.config/slackclip/credentials` for future use. If they expire, you'll be prompted to enter new ones.

## Output format

Messages are formatted as Markdown:

```markdown
**Jane Doe, at 2024-01-15 14:30:00:**
This is the first message in the thread.

**John Smith, at 2024-01-15 14:32:00:**
This is a reply with a [link](https://example.com) and some **bold text**.
```

## Shortcomings

- Multimedia (images, files) won't come through
- Reactions aren't included
- Only outputs Markdown format

## Credits

Originally created by [Heath Raftery](https://github.com/hraftery/slackclipper).
