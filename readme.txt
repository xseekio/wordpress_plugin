=== xSeek AI Bot Tracking ===
Contributors: xseek
Requires at least: 5.6
Tested up to: 6.6
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Server-side AI bot detection for WordPress. Tracks AI bot visits via xSeek’s API (bots don’t execute JavaScript).

== Description ==
Detects AI bots by User-Agent server-side and calls xSeek’s tracking endpoint when a bot is detected:

`POST https://www.xseek.io/api/track-ai-bot`

Request body (JSON):

{
  "botName": "string",
  "userAgent": "string",
  "url": "string",
  "websiteId": "string",
  "ip": "string (optional)",
  "referer": "string (optional)"
}

Patterns are based on xSeek’s bot database (see docs).

Docs: https://www.xseek.io/integrations/api

== Installation ==
1. Zip this folder as xseek-ai-bot-tracking.zip
2. WordPress → Plugins → Add New → Upload Plugin → Activate
3. Settings → xSeek AI Tracking → Enable xSeek tracking
4. Paste your xSeek Website ID + API Key (API key must have `ai_visits:push`)
5. (Optional) Enable including IP and/or Referer
6. Click "Send Test Event"

== Privacy ==
- Opt-in: disabled by default.
- Sends request metadata only (no bodies).
- Sends only for detected AI bots (not every request).
- API key is encrypted when possible using WordPress salts.

== Changelog ==
= 1.0.0 =
* Initial release: Server-side AI bot detection with xSeek API integration
* Privacy-first design: Opt-in by default, bot-only tracking, metadata only
* Secure configuration: Encrypted API key storage
* Admin interface: Easy configuration through WordPress admin
* Test functionality: Built-in test event sending