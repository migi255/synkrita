# Connect from the Codex CLI

Use the CLI on a workstation that can reach the approved Synkrita HTTPS endpoint and open a local browser. Get the MCP URL, your Synkrita login, synthetic IDs and a dedicated pre-registered **public** OAuth client ID from the operator. The operator enables authorization code with S256, public token exchange, exact redirect and resource binding. The Codex account and Synkrita OAuth login are separate. The commands below target the current CLI and their flags were checked against 0.170.0. [Codex MCP guide for CLI](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)

1. Ask the operator which loopback port to use. Substitute the approved URL and client ID. Add the configuration first using a fixed port so the provider can pin the callback. The add command can start a browser OAuth flow. If the redirect is still awaiting registration, stop that login after capturing the exact callback for the administrator.
   
   ```sh
   codex -c mcp_oauth_callback_port=4321 -c 'mcp_oauth_callback_url="http://127.0.0.1:4321/callback"' \
     mcp add synkrita --url https://YOUR-HOST/mcp --oauth-client-id YOUR_PUBLIC_CLIENT_ID
   ```

2. The administrator registers the exact redirect URI Codex displays or uses in the authorization request. Share only the redirect URI. With RFC 9207 issuer identification, Codex can use the stable path and requires an exact `iss` in the response. Otherwise it appends a server-specific callback ID. Ensure the provider pins the same port and path. Preserve any callback settings Codex saved in user configuration. Verify the provider issues the exact Synkrita audience and approved client claim before marking this client ready. [Codex callback rules](https://learn.chatgpt.com/docs/extend/mcp?surface=cli#oauth-client-registration-and-callbacks)
3. After registration, sign in with the same callback settings. Select the OS credential store if available. The reference provider configuration requests offline access when the provider advertises support and the client negotiates it.

   ```sh
   codex -c mcp_oauth_callback_port=4321 -c 'mcp_oauth_callback_url="http://127.0.0.1:4321/callback"' \
     mcp login synkrita --scopes research:access
   codex mcp list
   ```

4. In a new Codex session run `/mcp` and check the three tools. Ask Codex to call `read_public_observation` using the supplied synthetic receipt ID and show its citation. Check own, foreign and missing investigation IDs and the qualified decision. The operator records refresh, logout with `codex mcp logout synkrita`, reconnect and suspension for this CLI separately.

If the browser callback fails, check the actual redirect and the listener port on the workstation. A redirect mismatch or invalid issuer needs provider and client registration review. A 401 after sign-in needs provider claim checks and operator enrollment or suspension review. For 403 verify `research:access`. Never share the authorization URL, callback query, access token or refresh token. The client command syntax is locally checked. Real provider sign-in, tool behavior and refresh remain staging tests.
