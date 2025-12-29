package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
)

// Embed the React build directory
// This will be populated during build time by the Makefile
//
//go:embed admin-ui/build
var ReactBuildFS embed.FS

// ServeReactApp serves the embedded React application.
// It handles SPA routing by serving index.html for all non-API routes.
func ServeReactApp(c *gin.Context) {
	// Get the request path
	requestPath := c.Request.URL.Path

	// Don't serve UI for API routes or health check
	if strings.HasPrefix(requestPath, "/api/") || requestPath == "/health" {
		c.Status(http.StatusNotFound)
		return
	}

	// Root path or empty - serve index.html directly
	if requestPath == "/" || requestPath == "" {
		serveIndexHTML(c)
		return
	}

	// Try to serve the requested file from the embedded filesystem
	filePath := path.Join("admin-ui/build", strings.TrimPrefix(requestPath, "/"))

	// Check if file exists
	fileInfo, err := fs.Stat(ReactBuildFS, filePath)
	if err == nil && !fileInfo.IsDir() {
		// File exists and is not a directory, serve it
		c.FileFromFS(filePath, http.FS(ReactBuildFS))
		return
	}

	// File doesn't exist or is a directory - serve index.html for SPA routing
	// This allows React Router to handle the route on the client side
	serveIndexHTML(c)
}

// serveIndexHTML serves the index.html file directly from the embedded filesystem
func serveIndexHTML(c *gin.Context) {
	data, err := fs.ReadFile(ReactBuildFS, "admin-ui/build/index.html")
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", data)
}

// SetupUIRoutes configures routes for serving the React UI.
func SetupUIRoutes(r *gin.Engine) {
	// Serve static assets (js, css, images, etc.)
	// React build puts assets in build/static/, so mount that subdirectory at /static
	staticFS, err := fs.Sub(ReactBuildFS, "admin-ui/build/static")
	if err == nil {
		// Serve static files with proper caching headers
		r.StaticFS("/static", http.FS(staticFS))
	}

	// Serve other build assets (manifest, favicon, etc.)
	r.GET("/favicon.ico", func(c *gin.Context) {
		c.FileFromFS("admin-ui/build/favicon.ico", http.FS(ReactBuildFS))
	})
	r.GET("/manifest.json", func(c *gin.Context) {
		c.FileFromFS("admin-ui/build/manifest.json", http.FS(ReactBuildFS))
	})
	r.GET("/robots.txt", func(c *gin.Context) {
		c.FileFromFS("admin-ui/build/robots.txt", http.FS(ReactBuildFS))
	})

	// Catch-all route for SPA - must be registered last
	// Serves index.html for all non-API routes to support client-side routing
	r.NoRoute(ServeReactApp)
}
