# Deadshot 3D

A browser based first-person team deathmatch with a Three.js arena and real-time private rooms. Players can enter as guests or create an optional account.

## Play locally

Requires Node.js 20 or newer.

```bash
npm install
npm start
```

Open `http://localhost:3000`. Open the same address in another browser or device to test joining a room.

## Room rules

- Create a private room and share its six-character code.
- Each team accepts up to 8 players (16 players in a room).
- Players can switch teams and must ready up.
- The room creator is the host and starts the match after at least one player joins each team and everyone is ready.
- Matches last 10 minutes. Every elimination adds one point to the killer's team.
- Eliminated players redeploy after 3.5 seconds and can change weapons while waiting.
- The server checks movement speed, team limits, fire rate, ammunition, hits, damage, scores, and respawns.

## Hosting

Use a long-running Node web service because private rooms need a persistent WebSocket connection. **Railway is the simplest fit** for this project. Render also works as a Node web service with WebSockets enabled. Static-only hosting on Vercel or Render Static Sites cannot run the room server.

### Railway

1. Push the project to a Git repository and create a Railway service from it.
2. Add a Railway volume mounted at `/data`.
3. Set `DATA_DIR=/data` and set `SESSION_SECRET` to a long random secret in the service variables.
4. Deploy. Railway uses `npm start`; `/api/health` is the health endpoint.

The included `railway.json` selects the start command and health check. Room state lives in server memory and clears when the service restarts. Account records persist on the mounted volume.

### Render

The included `render.yaml` defines a Node web service, health check, persistent disk, and account data directory. Create the service from the repository and deploy the generated configuration.

## Accounts and guest play

Guest play needs no account. Optional accounts use email and password; passwords are stored as scrypt hashes, and signed sessions are held in the browser. Set a stable `SESSION_SECRET` and persistent `DATA_DIR` in production so sessions and account records survive deploys.

## Controls

- **WASD** move, **Shift** sprint, **Space** jump, **C** crouch
- **Mouse** aim and fire, **right mouse** aim down sights
- **R** reload, **1–4** choose rifle / sniper / shotgun / SMG
- **Tab** scoreboard
