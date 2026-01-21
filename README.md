# xSeek AEO Tracking WordPress Plugin

AEO integration for WordPress and server-side AI bot detection. Tracks AI bot visits via xSeek’s API (AI bots typically don’t execute JavaScript).

- **xSeek docs**: xSeek docs: https://www.xseek.io/integrations/wordpress

## What it does

Most AI bots fetch HTML but do not execute JavaScript, so client-side tracking misses the majority of AI traffic. This plugin detects AI bots server-side (via User-Agent) and sends an event to xSeek when a bot is detected.

**API endpoint**

`POST https://www.xseek.io/api/track-ai-bot`

**Request body (JSON)**

```json
{
  "botName": "string",
  "userAgent": "string",
  "url": "string",
  "websiteId": "string",
  "ip": "string (optional)",
  "referer": "string (optional)"
}
```

## Installation

1. Upload `xseek-aeo-tracking.zip`
2. WordPress → Plugins → Add New → Upload Plugin → Activate
3. WordPress → Settings → **xSeek AI Tracking**
4. Enable xSeek tracking (opt-in)
5. Paste your **xSeek Website ID** + **API Key** (API key must have `ai_visits:push`)
6. (Optional) Enable including IP and/or Referer
7. Click **Send Test Event** to verify configuration

## Privacy

- **Opt-in**: disabled by default.
- **Bot-only**: sends only for detected AI bots (not every request).
- **Metadata only**: no request/response bodies are sent.
- **API key storage**: encrypted at rest when possible (WordPress salts + libsodium).

## FAQ

### Does this track regular visitors?

No. It only sends events when the request User-Agent matches a known AI bot pattern.

### What data is sent to xSeek?

Required: `botName`, `userAgent`, `url`, `websiteId`. Optional (if enabled): `ip`, `referer`.

### I’m behind a proxy/CDN (Cloudflare, nginx). Will IP be correct?

If you enable “Include IP address”, the plugin uses `X-Forwarded-For` (left-most) when present, otherwise `REMOTE_ADDR`.

## Troubleshooting

- If the test event fails, confirm your API key has the `ai_visits:push` privilege and your Website ID is correct.
- Some hosts block outgoing HTTP requests; check your server/firewall rules if you never see events.

## License

MIT — see `LICENSE`.



