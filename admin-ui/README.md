# KProxy Admin UI

This is the React-based admin interface for KProxy. The UI is built and embedded into the Go binary for easy deployment.

## Development

To run the UI in development mode (with hot reload):

```bash
cd admin-ui
npm install
npm start
```

The development server will start on `http://localhost:3000` and will proxy API requests to `https://localhost:8443/api`.

## Building

The UI is automatically built and embedded into the Go binary when you run:

```bash
make build
```

This will:
1. Install npm dependencies
2. Build the React app for production (`npm run build`)
3. Copy the build to `web/admin-ui/build` for Go embedding
4. Build the Go binary with the embedded UI

## Production

When served from the Go binary, the UI will be available at the root path (`/`) and will use relative API paths (`/api/*`).

## API Configuration

The UI connects to the API using environment-aware configuration:

- **Development** (`npm start`): Uses `https://localhost:8443/api`
- **Production** (embedded in Go): Uses `/api` (relative path)
- **Custom**: Set `REACT_APP_API_URL` environment variable

## Project Structure

```
admin-ui/
├── public/          # Static assets
├── src/
│   ├── components/  # Reusable React components
│   ├── pages/       # Page components (Dashboard, Devices, etc.)
│   ├── services/    # API service layer
│   ├── App.js       # Main app component with routing
│   └── App.css      # Global styles
├── package.json     # Dependencies and scripts
└── README.md        # This file
```

## Features

- **Authentication**: JWT-based login/logout
- **Dashboard**: Overview statistics and metrics
- **Devices**: Manage proxy devices (CRUD operations)
- **Profiles**: Manage access profiles
- **Rules**: Configure filtering rules (domain, time, usage limits)
- **Logs**: View request and DNS logs
- **Dark Theme**: Professional dark UI
- **Responsive**: Works on mobile, tablet, and desktop

## Dependencies

- React 19
- React Router 7
- Axios (HTTP client)
- Create React App (build tooling)
