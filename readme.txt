=== xSeek AI Bot Tracking ===
Contributors: xseek
Tags: ai, bots, analytics, seo, aeo
Requires at least: 5.6
Tested up to: 6.6
Stable tag: 1.0.0
Requires PHP: 7.0
License: MIT
License URI: https://opensource.org/license/mit/

Server-side AI bot detection for WordPress. Tracks AI bot visits via xSeek’s API (AI bots typically don’t execute JavaScript).

== Description ==
Most AI bots fetch HTML but do not execute JavaScript, so client-side tracking misses the majority of AI traffic. This plugin detects AI bots server-side (via User-Agent) and sends an event to xSeek when a bot is detected.

**API endpoint**

`POST https://www.xseek.io/api/track-ai-bot`

**Request body (JSON)**

{
  "botName": "string",
  "userAgent": "string",
  "url": "string",
  "websiteId": "string",
  "ip": "string (optional)",
  "referer": "string (optional)"
}

Bot patterns are based on xSeek’s bot database (see docs).

Docs: https://www.xseek.io/integrations/api

== Installation ==
1. Upload `xseek-ai-bot-tracking.zip`
2. WordPress → Plugins → Add New → Upload Plugin → Activate
3. Settings → xSeek AI Tracking
4. Enable xSeek tracking (opt-in)
5. Paste your xSeek Website ID + API Key (API key must have `ai_visits:push`)
6. (Optional) Enable including IP and/or Referer
7. Click “Send Test Event” to verify configuration

== Privacy ==
- Opt-in: disabled by default.
- Sends request metadata only (no bodies).
- Sends only for detected AI bots (not every request).
- API key is encrypted at rest when possible (using WordPress salts + libsodium).

== Frequently Asked Questions ==

= Does this track regular visitors? =
No. It only sends events when the request User-Agent matches a known AI bot pattern.

= What data is sent to xSeek? =
Required: `botName`, `userAgent`, `url`, `websiteId`. Optional (if enabled): `ip`, `referer`.

= Why is this server-side? =
Because most AI bots do not execute JavaScript, so client-side tracking misses them. See xSeek’s docs.

= I’m behind a proxy/CDN (Cloudflare, nginx). Will IP be correct? =
If you enable “Include IP address”, the plugin uses `X-Forwarded-For` (left-most) when present, otherwise `REMOTE_ADDR`.

== Troubleshooting ==
- If the test event fails, confirm your API key has the `ai_visits:push` privilege and your Website ID is correct.
- Some hosts block outgoing HTTP requests; check your server/firewall rules if you never see events.

== Changelog ==
= 1.0.0 =
* Initial release: Server-side AI bot detection with xSeek API integration
* Privacy-first design: Opt-in by default, bot-only tracking, metadata only
* Secure configuration: Encrypted API key storage
* Admin interface: Easy configuration through WordPress admin
* Test functionality: Built-in test event sending