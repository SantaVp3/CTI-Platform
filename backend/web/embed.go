package web

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
)

//go:embed static/*
var staticFiles embed.FS

// GetStaticFS returns the embedded static file system
func GetStaticFS() fs.FS {
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	return staticFS
}

// SPAHandler handles serving the React SPA with proper routing fallbacks
func SPAHandler() http.Handler {
	staticFS := GetStaticFS()
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Clean the path
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		// Try to serve the requested file
		if file, err := staticFS.Open(path); err == nil {
			defer file.Close()
			
			// Get file info to check if it's a directory
			if stat, err := file.Stat(); err == nil && !stat.IsDir() {
				// Set appropriate content type
				ext := filepath.Ext(path)
				switch ext {
				case ".html":
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
				case ".js":
					w.Header().Set("Content-Type", "application/javascript")
				case ".css":
					w.Header().Set("Content-Type", "text/css")
				case ".json":
					w.Header().Set("Content-Type", "application/json")
				case ".svg":
					w.Header().Set("Content-Type", "image/svg+xml")
				case ".png":
					w.Header().Set("Content-Type", "image/png")
				case ".jpg", ".jpeg":
					w.Header().Set("Content-Type", "image/jpeg")
				case ".ico":
					w.Header().Set("Content-Type", "image/x-icon")
				}
				
				// Serve the file
				if seeker, ok := file.(io.ReadSeeker); ok {
					http.ServeContent(w, r, path, stat.ModTime(), seeker)
				} else {
					// Fallback: read all content and serve
					content, err := io.ReadAll(file)
					if err != nil {
						http.Error(w, "Error reading file", http.StatusInternalServerError)
						return
					}
					http.ServeContent(w, r, path, stat.ModTime(), strings.NewReader(string(content)))
				}
				return
			}
		}

		// If file not found or is a directory, serve index.html for SPA routing
		if indexFile, err := staticFS.Open("index.html"); err == nil {
			defer indexFile.Close()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if stat, err := indexFile.Stat(); err == nil {
				if seeker, ok := indexFile.(io.ReadSeeker); ok {
					http.ServeContent(w, r, "index.html", stat.ModTime(), seeker)
				} else {
					// Fallback: read all content and serve
					content, err := io.ReadAll(indexFile)
					if err != nil {
						http.Error(w, "Error reading index.html", http.StatusInternalServerError)
						return
					}
					http.ServeContent(w, r, "index.html", stat.ModTime(), strings.NewReader(string(content)))
				}
				return
			}
		}

		// If we can't serve index.html, return 404
		http.NotFound(w, r)
	})
}
