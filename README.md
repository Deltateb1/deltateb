# Deltateb — independent starter

Deltateb is a self-hosted short-video application starter. It does **not** use Hatchable.

## Included in this first version

- Username/password registration and login
- SQLite database (created automatically)
- Video uploads (up to 100 MB per file)
- For You and Following feeds
- Likes, comments and follows
- Creator search
- Responsive web/PWA interface

## Requirements

Install **Node.js 18 or newer** and npm. The project uses `better-sqlite3`, which may need build tools on some systems. On Windows, use a current supported Windows version and install the Node.js LTS release.

## Run locally

1. Extract this ZIP.
2. Open a terminal in the extracted `deltateb-independent` folder.
3. Install dependencies:

   ```bash
   npm install
   ```

4. Start the server:

   ```bash
   npm start
   ```

5. Open `http://localhost:3000`.

The database is created at `data/deltateb.sqlite`. Uploaded videos are stored in `public/uploads/`.

## Important before public deployment

This is a development MVP, not a hardened production service. Before exposing it to the public:

- Set a long random `SESSION_SECRET` environment variable.
- Serve the site over HTTPS (`NODE_ENV=production` enables secure cookies).
- Put uploads on persistent storage and configure backups.
- Add upload scanning, quotas, moderation/reporting and content takedown tools.
- Add CSRF protection and stricter per-user rate limits.
- Use a reverse proxy/object storage and video transcoding for scale.
- Review privacy, copyright and local legal requirements.

The included service worker caches the app shell only; it does not cache API responses or uploaded videos.

## Android

This first package is a responsive web app/PWA. It is **not an APK**. Once the web app is running and deployed over HTTPS, it can be wrapped with Capacitor to produce an Android project. Building an APK requires Android Studio/Android SDK on a supported computer.

## Windows 7 note

Current Node.js releases no longer support Windows 7. If you are still using Windows 7, this project will need to be run on a supported computer or hosted online; do not expect a modern Node.js install to work reliably on Windows 7.
