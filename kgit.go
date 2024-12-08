package kgit

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Error types
var (
	ErrFileNotFound = errors.New("file not found")
)

// GitProvider represents different git hosting services
type GitProvider int

const (
	GitHub GitProvider = iota
	GitLab
	Bitbucket
)

// GitConfig holds configuration for git operations
type GitConfig struct {
	Provider GitProvider
	Token    string
	BaseURL  string // Optional: for self-hosted instances
}

// FileChangeType represents the type of change that occurred
type FileChangeType int

const (
	FileCreated FileChangeType = iota
	FileModified
	FileDeleted
)

// FileChange contains information about the change that occurred
type FileChange struct {
	Type     FileChangeType
	SHA      string
	FileInfo FileInfo
}

// FileInfo contains file metadata
type FileInfo struct {
	SHA       string    `json:"sha,omitempty"`
	Size      int       `json:"size,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// RateLimit contains API rate limit information
type RateLimit struct {
	Limit     int
	Remaining int
	Reset     time.Time
}

// DownloadGitFile downloads a file from any supported git provider
func DownloadGitFile(repoURL, filePath string, config GitConfig) ([]byte, error) {
	switch config.Provider {
	case GitHub:
		return downloadGitHubFile(repoURL, filePath, config)
	case GitLab:
		return downloadGitLabFile(repoURL, filePath, config)
	case Bitbucket:
		return downloadBitbucketFile(repoURL, filePath, config)
	default:
		return nil, fmt.Errorf("unsupported git provider")
	}
}

// UploadGitFile uploads a file to any supported git provider
func UploadGitFile(repoURL, filePath string, content []byte, message string, config GitConfig) error {
	switch config.Provider {
	case GitHub:
		return uploadGitHubFile(repoURL, filePath, content, message, config)
	case GitLab:
		return uploadGitLabFile(repoURL, filePath, content, message, config)
	case Bitbucket:
		return uploadBitbucketFile(repoURL, filePath, content, message, config)
	default:
		return fmt.Errorf("unsupported git provider")
	}
}

// DeleteGitFile deletes a file from any supported git provider
func DeleteGitFile(repoURL, filePath string, config GitConfig) error {
	switch config.Provider {
	case GitHub:
		return deleteGitHubFile(repoURL, filePath, config)
	case GitLab:
		return deleteGitLabFile(repoURL, filePath, config)
	case Bitbucket:
		return deleteBitbucketFile(repoURL, filePath, config)
	default:
		return fmt.Errorf("unsupported git provider")
	}
}

// WatchGitFile watches a file in any supported git provider
func WatchGitFile(repoURL, filePath string, interval int, config GitConfig) (<-chan FileChange, <-chan error) {
	switch config.Provider {
	case GitHub:
		return watchGitHubFile(repoURL, filePath, interval, config)
	case GitLab:
		return watchGitLabFile(repoURL, filePath, interval, config)
	case Bitbucket:
		return watchBitbucketFile(repoURL, filePath, interval, config)
	default:
		errors := make(chan error, 1)
		errors <- fmt.Errorf("unsupported git provider")
		close(errors)
		return nil, errors
	}
}

// FileExistsGit checks if a file exists on any supported git provider
func FileExistsGit(repoURL, filePath string, config GitConfig) (bool, error) {
	switch config.Provider {
	case GitHub:
		return fileExistsGitHub(repoURL, filePath, config)
	case GitLab:
		return fileExistsGitLab(repoURL, filePath, config)
	case Bitbucket:
		return fileExistsBitbucket(repoURL, filePath, config)
	default:
		return false, fmt.Errorf("unsupported git provider")
	}
}

// Helper functions for each provider
func CreateGitHubRepository(name string, isPrivate bool, config GitConfig) error {
	if config.Token == "" {
		return fmt.Errorf("token is required for creating repositories")
	}

	requestBody := map[string]interface{}{
		"name":      name,
		"private":   isPrivate,
		"auto_init": true,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("error encoding request: %v", err)
	}

	apiURL := "https://api.github.com/user/repos"
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Add("Authorization", "token "+config.Token)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error creating repository (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// GitHub specific implementations
func downloadGitHubFile(repoURL, filePath string, config GitConfig) ([]byte, error) {
	// Convert github.com URL to raw content URL
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "github.com/")

	// Try different branches
	branches := []string{"master", "main", "HEAD", "dev", "development"}
	var lastErr error
	var isPrivateRepo bool

	for _, branch := range branches {
		rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", repoURL, branch, filePath)

		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request: %v", err)
		}

		if config.Token != "" {
			req.Header.Add("Authorization", "Bearer "+config.Token)
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("error making request to %s: %v", branch, err)
			continue
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			return io.ReadAll(resp.Body)
		case http.StatusNotFound:
			lastErr = fmt.Errorf("file not found in %s branch", branch)
		case http.StatusUnauthorized, http.StatusForbidden:
			isPrivateRepo = true
			lastErr = fmt.Errorf("repository requires authentication")
		default:
			lastErr = fmt.Errorf("unexpected status in %s branch: %s", branch, resp.Status)
		}
	}

	if isPrivateRepo {
		return nil, fmt.Errorf("repository is private, please provide a valid GitHub token")
	}
	return nil, fmt.Errorf("file not found in any branch: %v", lastErr)
}

func uploadGitHubFile(repoURL, filePath string, content []byte, message string, config GitConfig) error {
	if config.Token == "" {
		return fmt.Errorf("token is required for uploading files")
	}

	// Convert github.com URL to API URL
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "github.com/")

	// Prepare the request URL
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", repoURL, filePath)

	// Prepare the request body
	requestBody := map[string]interface{}{
		"message": message,
		"content": base64.StdEncoding.EncodeToString(content),
	}

	// Check if file exists to get its SHA
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Authorization", "Bearer "+config.Token)
	resp, err := http.DefaultClient.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		var fileInfo struct {
			SHA string `json:"sha"`
		}
		json.NewDecoder(resp.Body).Decode(&fileInfo)
		resp.Body.Close()
		requestBody["sha"] = fileInfo.SHA
	}

	// Convert request body to JSON
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("error preparing request: %v", err)
	}

	// Create the PUT request
	req, err = http.NewRequest("PUT", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+config.Token)
	req.Header.Add("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error uploading file (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

func deleteGitHubFile(repoURL, filePath string, config GitConfig) error {
	if config.Token == "" {
		return fmt.Errorf("token is required for deleting files")
	}

	// Convert github.com URL to API URL
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "github.com/")

	// Prepare the request URL
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", repoURL, filePath)

	// First get the file's SHA
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Authorization", "Bearer "+config.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error getting file info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("file not found or not accessible")
	}

	var fileInfo struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fileInfo); err != nil {
		return fmt.Errorf("error reading file info: %v", err)
	}

	// Prepare the delete request
	requestBody := map[string]interface{}{
		"message": "Delete file",
		"sha":     fileInfo.SHA,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("error preparing request: %v", err)
	}

	// Create the DELETE request
	req, err = http.NewRequest("DELETE", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+config.Token)
	req.Header.Add("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error deleting file (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

func watchGitHubFile(repoURL, filePath string, interval int, config GitConfig) (chan FileChange, chan error) {
	changes := make(chan FileChange)
	errors := make(chan error)

	var lastSHA string
	var fileExists bool
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s",
		strings.TrimPrefix(strings.TrimPrefix(repoURL, "https://"), "github.com/"),
		filePath)

	go func() {
		defer close(changes)
		defer close(errors)

		for {
			req, err := http.NewRequest("GET", apiURL, nil)
			if err != nil {
				errors <- fmt.Errorf("error creating request: %v", err)
				return
			}

			if config.Token != "" {
				req.Header.Add("Authorization", "Bearer "+config.Token)
			}

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				errors <- fmt.Errorf("error making request: %v", err)
				time.Sleep(time.Duration(interval) * time.Second)
				continue
			}

			// Check rate limits
			rateLimit := getRateLimit(resp)
			if rateLimit.Remaining == 0 {
				waitDuration := time.Until(rateLimit.Reset)
				errors <- fmt.Errorf("rate limit exceeded, waiting %v until reset", waitDuration.Round(time.Second))
				time.Sleep(waitDuration)
				resp.Body.Close()
				continue
			}

			// If we're close to rate limit, increase the interval
			if rateLimit.Remaining < 100 {
				newInterval := interval * 2
				errors <- fmt.Errorf("approaching rate limit (%d remaining), increasing interval to %d seconds",
					rateLimit.Remaining, newInterval)
				interval = newInterval
			}

			switch resp.StatusCode {
			case http.StatusOK:
				var fileInfo FileInfo
				if err := json.NewDecoder(resp.Body).Decode(&fileInfo); err != nil {
					errors <- fmt.Errorf("error decoding response: %v", err)
					resp.Body.Close()
					time.Sleep(time.Duration(interval) * time.Second)
					continue
				}
				resp.Body.Close()

				if !fileExists {
					fileExists = true
					lastSHA = fileInfo.SHA
					changes <- FileChange{
						Type:     FileCreated,
						SHA:      fileInfo.SHA,
						FileInfo: fileInfo,
					}
				} else if lastSHA != fileInfo.SHA {
					lastSHA = fileInfo.SHA
					changes <- FileChange{
						Type:     FileModified,
						SHA:      fileInfo.SHA,
						FileInfo: fileInfo,
					}
				}

			case http.StatusNotFound:
				if fileExists {
					fileExists = false
					lastSHA = ""
					changes <- FileChange{
						Type: FileDeleted,
					}
				}
				resp.Body.Close()

			case http.StatusForbidden:
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if strings.Contains(string(body), "rate limit exceeded") {
					waitDuration := time.Until(rateLimit.Reset)
					errors <- fmt.Errorf("rate limit exceeded, waiting %v until reset", waitDuration.Round(time.Second))
					time.Sleep(waitDuration)
					continue
				}
				errors <- fmt.Errorf("forbidden: %s", body)
				return

			case http.StatusUnauthorized:
				resp.Body.Close()
				errors <- fmt.Errorf("authentication required or token invalid")
				return

			default:
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				errors <- fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, body)
				time.Sleep(time.Duration(interval) * time.Second)
				continue
			}

			time.Sleep(time.Duration(interval) * time.Second)
		}
	}()

	return changes, errors
}

// GitLab specific implementations
func getGitLabProjectID(repoURL string, config GitConfig) (int, error) {
	client := &http.Client{}
	projectPath := strings.TrimPrefix(repoURL, "https://")
	projectPath = strings.TrimPrefix(projectPath, "gitlab.com/")
	projectPath = url.PathEscape(projectPath)

	apiURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s", projectPath)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return 0, fmt.Errorf("error creating request: %v", err)
	}

	if config.Token != "" {
		req.Header.Add("PRIVATE-TOKEN", config.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("error getting project info: %s", resp.Status)
	}

	var project struct {
		ID int `json:"id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return 0, fmt.Errorf("error decoding response: %v", err)
	}

	return project.ID, nil
}

func downloadGitLabFile(repoURL, filePath string, config GitConfig) ([]byte, error) {
	// First get project info to get the numeric ID
	client := &http.Client{}
	projectPath := strings.TrimPrefix(repoURL, "https://")
	projectPath = strings.TrimPrefix(projectPath, "gitlab.com/")
	projectPath = url.PathEscape(projectPath)

	infoURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s", projectPath)
	req, err := http.NewRequest("GET", infoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating project info request: %v", err)
	}

	if config.Token != "" {
		req.Header.Add("PRIVATE-TOKEN", config.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting project info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting project info: %s", resp.Status)
	}

	var projectInfo struct {
		ID            int    `json:"id"`
		DefaultBranch string `json:"default_branch"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&projectInfo); err != nil {
		return nil, fmt.Errorf("error decoding project info: %v", err)
	}

	// Get the file content
	encodedPath := strings.ReplaceAll(filePath, "/", "%2F")
	fileURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s/raw?ref=%s",
		projectInfo.ID, encodedPath, projectInfo.DefaultBranch)

	req, err = http.NewRequest("GET", fileURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating file request: %v", err)
	}

	if config.Token != "" {
		req.Header.Add("PRIVATE-TOKEN", config.Token)
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrFileNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting file: %s", resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading file content: %v", err)
	}

	return content, nil
}

func uploadGitLabFile(repoURL, filePath string, content []byte, commitMessage string, config GitConfig) error {
	// First get project info to get the numeric ID
	client := &http.Client{}
	projectPath := strings.TrimPrefix(repoURL, "https://")
	projectPath = strings.TrimPrefix(projectPath, "gitlab.com/")
	projectPath = url.PathEscape(projectPath)

	infoURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s", projectPath)
	req, err := http.NewRequest("GET", infoURL, nil)
	if err != nil {
		return fmt.Errorf("error creating project info request: %v", err)
	}

	if config.Token != "" {
		req.Header.Add("PRIVATE-TOKEN", config.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error getting project info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error getting project info: %s", resp.Status)
	}

	var projectInfo struct {
		ID            int    `json:"id"`
		DefaultBranch string `json:"default_branch"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&projectInfo); err != nil {
		return fmt.Errorf("error decoding project info: %v", err)
	}

	// Create/update the file
	encodedPath := strings.ReplaceAll(filePath, "/", "%2F")
	createFileURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s",
		projectInfo.ID, encodedPath)

	// Check if file exists
	checkURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s?ref=%s",
		projectInfo.ID, encodedPath, projectInfo.DefaultBranch)

	req, err = http.NewRequest("GET", checkURL, nil)
	if err != nil {
		return fmt.Errorf("error creating check request: %v", err)
	}

	if config.Token != "" {
		req.Header.Add("PRIVATE-TOKEN", config.Token)
	}

	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("error checking file: %v", err)
	}
	defer resp.Body.Close()

	// Use PUT for existing files, POST for new files
	method := "POST"
	if resp.StatusCode == http.StatusOK {
		method = "PUT"
	}

	createFileBody := struct {
		Branch        string `json:"branch"`
		Content       string `json:"content"`
		CommitMessage string `json:"commit_message"`
		AuthorEmail   string `json:"author_email"`
		AuthorName    string `json:"author_name"`
	}{
		Branch:        projectInfo.DefaultBranch,
		Content:       base64.StdEncoding.EncodeToString(content),
		CommitMessage: commitMessage,
		AuthorEmail:   "bot@example.com",
		AuthorName:    "Bot",
	}

	jsonBody, err := json.Marshal(createFileBody)
	if err != nil {
		return fmt.Errorf("error encoding file request: %v", err)
	}

	req, err = http.NewRequest(method, createFileURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error creating file request: %v", err)
	}

	if config.Token != "" {
		req.Header.Add("PRIVATE-TOKEN", config.Token)
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error creating file (status %d): %s", resp.StatusCode, body)
	}

	return nil
}

func deleteGitLabFile(repoURL, filePath string, config GitConfig) error {
	// First get project info to get the numeric ID
	client := &http.Client{}
	projectPath := strings.TrimPrefix(repoURL, "https://")
	projectPath = strings.TrimPrefix(projectPath, "gitlab.com/")
	projectPath = url.PathEscape(projectPath)

	infoURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s", projectPath)
	req, err := http.NewRequest("GET", infoURL, nil)
	if err != nil {
		return fmt.Errorf("error creating project info request: %v", err)
	}

	if config.Token != "" {
		req.Header.Add("PRIVATE-TOKEN", config.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error getting project info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error getting project info: %s", resp.Status)
	}

	var projectInfo struct {
		ID            int    `json:"id"`
		DefaultBranch string `json:"default_branch"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&projectInfo); err != nil {
		return fmt.Errorf("error decoding project info: %v", err)
	}

	// Delete the file
	encodedPath := strings.ReplaceAll(filePath, "/", "%2F")
	deleteURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s",
		projectInfo.ID, encodedPath)

	deleteBody := struct {
		Branch        string `json:"branch"`
		CommitMessage string `json:"commit_message"`
		AuthorEmail   string `json:"author_email"`
		AuthorName    string `json:"author_name"`
	}{
		Branch:        projectInfo.DefaultBranch,
		CommitMessage: "Delete file via API",
		AuthorEmail:   "bot@example.com",
		AuthorName:    "Bot",
	}

	jsonBody, err := json.Marshal(deleteBody)
	if err != nil {
		return fmt.Errorf("error encoding delete request: %v", err)
	}

	req, err = http.NewRequest("DELETE", deleteURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("error creating delete request: %v", err)
	}

	if config.Token != "" {
		req.Header.Add("PRIVATE-TOKEN", config.Token)
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("error deleting file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error deleting file (status %d): %s", resp.StatusCode, respBody)
	}

	return nil
}

func watchGitLabFile(repoURL, filePath string, interval int, config GitConfig) (<-chan FileChange, <-chan error) {
	changes := make(chan FileChange)
	errors := make(chan error)
	done := make(chan struct{})

	go func() {
		defer close(changes)
		defer close(errors)

		var lastSHA string
		firstRun := true

		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// Get project info
				client := &http.Client{}
				projectPath := strings.TrimPrefix(repoURL, "https://")
				projectPath = strings.TrimPrefix(projectPath, "gitlab.com/")
				projectPath = url.PathEscape(projectPath)

				infoURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s", projectPath)
				req, err := http.NewRequest("GET", infoURL, nil)
				if err != nil {
					errors <- fmt.Errorf("error creating project info request: %v", err)
					continue
				}

				if config.Token != "" {
					req.Header.Add("PRIVATE-TOKEN", config.Token)
				}

				resp, err := client.Do(req)
				if err != nil {
					errors <- fmt.Errorf("error getting project info: %v", err)
					continue
				}

				if resp.StatusCode != http.StatusOK {
					resp.Body.Close()
					errors <- fmt.Errorf("error getting project info: %s", resp.Status)
					continue
				}

				var projectInfo struct {
					ID            int    `json:"id"`
					DefaultBranch string `json:"default_branch"`
				}

				if err := json.NewDecoder(resp.Body).Decode(&projectInfo); err != nil {
					resp.Body.Close()
					errors <- fmt.Errorf("error decoding project info: %v", err)
					continue
				}
				resp.Body.Close()

				// Get file info
				encodedPath := strings.ReplaceAll(filePath, "/", "%2F")
				fileURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s?ref=%s",
					projectInfo.ID, encodedPath, projectInfo.DefaultBranch)

				req, err = http.NewRequest("GET", fileURL, nil)
				if err != nil {
					errors <- fmt.Errorf("error creating file request: %v", err)
					continue
				}

				if config.Token != "" {
					req.Header.Add("PRIVATE-TOKEN", config.Token)
				}

				resp, err = client.Do(req)
				if err != nil {
					errors <- fmt.Errorf("error getting file: %v", err)
					continue
				}

				switch resp.StatusCode {
				case http.StatusOK:
					var fileInfo struct {
						BlobID string `json:"blob_id"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&fileInfo); err != nil {
						resp.Body.Close()
						errors <- fmt.Errorf("error decoding file info: %v", err)
						continue
					}
					resp.Body.Close()

					if firstRun {
						lastSHA = fileInfo.BlobID
						firstRun = false
						continue
					}

					if fileInfo.BlobID != lastSHA {
						changes <- FileChange{
							Type: FileModified,
							SHA:  fileInfo.BlobID,
						}
						lastSHA = fileInfo.BlobID
					}

				case http.StatusNotFound:
					resp.Body.Close()
					if !firstRun && lastSHA != "" {
						changes <- FileChange{
							Type: FileDeleted,
						}
						lastSHA = ""
					}
					firstRun = false

				default:
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					errors <- fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, body)
				}
			}
		}
	}()

	return changes, errors
}

func fileExistsGitLab(repoURL, filePath string, config GitConfig) (bool, error) {
	// First get project info to get the numeric ID
	client := &http.Client{}
	projectPath := strings.TrimPrefix(repoURL, "https://")
	projectPath = strings.TrimPrefix(projectPath, "gitlab.com/")
	projectPath = url.PathEscape(projectPath)

	infoURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s", projectPath)
	req, err := http.NewRequest("GET", infoURL, nil)
	if err != nil {
		return false, fmt.Errorf("error creating project info request: %v", err)
	}

	if config.Token != "" {
		req.Header.Add("PRIVATE-TOKEN", config.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error getting project info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("error getting project info: %s", resp.Status)
	}

	var projectInfo struct {
		ID            int    `json:"id"`
		DefaultBranch string `json:"default_branch"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&projectInfo); err != nil {
		return false, fmt.Errorf("error decoding project info: %v", err)
	}

	// Check if file exists
	encodedPath := strings.ReplaceAll(filePath, "/", "%2F")
	checkURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%d/repository/files/%s?ref=%s",
		projectInfo.ID, encodedPath, projectInfo.DefaultBranch)

	req, err = http.NewRequest("GET", checkURL, nil)
	if err != nil {
		return false, fmt.Errorf("error creating check request: %v", err)
	}

	if config.Token != "" {
		req.Header.Add("PRIVATE-TOKEN", config.Token)
	}

	resp, err = client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error checking file: %v", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// Bitbucket specific implementations
func downloadBitbucketFile(repoURL, filePath string, config GitConfig) ([]byte, error) {
	// First get project info
	client := &http.Client{}
	projectPath := strings.TrimPrefix(repoURL, "https://")
	projectPath = strings.TrimPrefix(projectPath, "bitbucket.org/")

	// Get file content
	fileURL := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s/src/master/%s",
		projectPath, url.PathEscape(filePath))

	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating file request: %v", err)
	}

	if config.Token != "" {
		// Extract username from repository path
		parts := strings.Split(projectPath, "/")
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid repository path format")
		}
		username := parts[0]
		req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+config.Token)))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error getting file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrFileNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting file: %s", resp.Status)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading file content: %v", err)
	}

	return content, nil
}

func uploadBitbucketFile(repoURL, filePath string, content []byte, commitMessage string, config GitConfig) error {
	// First get project info
	client := &http.Client{}
	projectPath := strings.TrimPrefix(repoURL, "https://")
	projectPath = strings.TrimPrefix(projectPath, "bitbucket.org/")

	// Create/update the file
	fileURL := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s/src", projectPath)

	// Create form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add the file
	part, err := writer.CreateFormFile(filePath, filePath)
	if err != nil {
		return fmt.Errorf("error creating form file: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		return fmt.Errorf("error writing content: %v", err)
	}

	// Add commit message
	if err := writer.WriteField("message", commitMessage); err != nil {
		return fmt.Errorf("error writing commit message: %v", err)
	}

	// Add branch
	if err := writer.WriteField("branch", "master"); err != nil {
		return fmt.Errorf("error writing branch: %v", err)
	}

	writer.Close()

	req, err := http.NewRequest("POST", fileURL, body)
	if err != nil {
		return fmt.Errorf("error creating file request: %v", err)
	}

	if config.Token != "" {
		// Extract username from repository path
		parts := strings.Split(projectPath, "/")
		if len(parts) < 2 {
			return fmt.Errorf("invalid repository path format")
		}
		username := parts[0]
		req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+config.Token)))
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error uploading file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error uploading file (status %d): %s", resp.StatusCode, respBody)
	}

	return nil
}

func deleteBitbucketFile(repoURL, filePath string, config GitConfig) error {
	// First get project info
	client := &http.Client{}
	projectPath := strings.TrimPrefix(repoURL, "https://")
	projectPath = strings.TrimPrefix(projectPath, "bitbucket.org/")

	// Create delete request
	fileURL := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s/src", projectPath)

	// Create form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add file to delete
	if err := writer.WriteField("files", filePath); err != nil {
		return fmt.Errorf("error writing file path: %v", err)
	}

	// Add commit message
	if err := writer.WriteField("message", "Delete file via API"); err != nil {
		return fmt.Errorf("error writing commit message: %v", err)
	}

	// Add branch
	if err := writer.WriteField("branch", "master"); err != nil {
		return fmt.Errorf("error writing branch: %v", err)
	}

	writer.Close()

	req, err := http.NewRequest("POST", fileURL, body)
	if err != nil {
		return fmt.Errorf("error creating delete request: %v", err)
	}

	if config.Token != "" {
		// Extract username from repository path
		parts := strings.Split(projectPath, "/")
		if len(parts) < 2 {
			return fmt.Errorf("invalid repository path format")
		}
		username := parts[0]
		req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+config.Token)))
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error deleting file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error deleting file (status %d): %s", resp.StatusCode, respBody)
	}

	return nil
}

func fileExistsBitbucket(repoURL, filePath string, config GitConfig) (bool, error) {
	// First get project info
	client := &http.Client{}
	projectPath := strings.TrimPrefix(repoURL, "https://")
	projectPath = strings.TrimPrefix(projectPath, "bitbucket.org/")

	// Check if file exists
	fileURL := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s/src/master/%s",
		projectPath, url.PathEscape(filePath))

	req, err := http.NewRequest("GET", fileURL, nil)
	if err != nil {
		return false, fmt.Errorf("error creating file request: %v", err)
	}

	if config.Token != "" {
		// Extract username from repository path
		parts := strings.Split(projectPath, "/")
		if len(parts) < 2 {
			return false, fmt.Errorf("invalid repository path format")
		}
		username := parts[0]
		req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+config.Token)))
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error checking file: %v", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

func watchBitbucketFile(repoURL, filePath string, interval int, config GitConfig) (<-chan FileChange, <-chan error) {
	changes := make(chan FileChange)
	errors := make(chan error)
	done := make(chan struct{})

	go func() {
		defer close(changes)
		defer close(errors)

		var lastContent string
		firstRun := true

		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		// Extract username from repository path
		projectPath := strings.TrimPrefix(repoURL, "https://")
		projectPath = strings.TrimPrefix(projectPath, "bitbucket.org/")
		parts := strings.Split(projectPath, "/")
		if len(parts) < 2 {
			errors <- fmt.Errorf("invalid repository path format")
			return
		}
		username := parts[0]

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// Get file info
				client := &http.Client{}

				fileURL := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s/src/master/%s",
					projectPath, url.PathEscape(filePath))

				req, err := http.NewRequest("GET", fileURL, nil)
				if err != nil {
					errors <- fmt.Errorf("error creating file request: %v", err)
					continue
				}

				if config.Token != "" {
					req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+config.Token)))
				}

				resp, err := client.Do(req)
				if err != nil {
					errors <- fmt.Errorf("error getting file: %v", err)
					continue
				}

				switch resp.StatusCode {
				case http.StatusOK:
					content, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil {
						errors <- fmt.Errorf("error reading file content: %v", err)
						continue
					}

					currentContent := string(content)
					if firstRun {
						lastContent = currentContent
						firstRun = false
						continue
					}

					if currentContent != lastContent {
						changes <- FileChange{
							Type: FileModified,
							SHA:  fmt.Sprintf("%x", sha256.Sum256(content)), // Generate hash from content
						}
						lastContent = currentContent
					}

				case http.StatusNotFound:
					resp.Body.Close()
					if !firstRun && lastContent != "" {
						changes <- FileChange{
							Type: FileDeleted,
						}
						lastContent = ""
					}
					firstRun = false

				default:
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					errors <- fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, body)
				}
			}
		}
	}()

	return changes, errors
}

// Helper functions
func getRateLimit(resp *http.Response) *RateLimit {
	limit, _ := strconv.Atoi(resp.Header.Get("X-RateLimit-Limit"))
	remaining, _ := strconv.Atoi(resp.Header.Get("X-RateLimit-Remaining"))
	reset, _ := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)

	return &RateLimit{
		Limit:     limit,
		Remaining: remaining,
		Reset:     time.Unix(reset, 0),
	}
}

func fileExistsGitHub(repoURL, filePath string, config GitConfig) (bool, error) {
	// Convert github.com URL to API URL
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "github.com/")

	// Prepare the request URL
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", repoURL, filePath)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return false, fmt.Errorf("error creating request: %v", err)
	}

	if config.Token != "" {
		req.Header.Add("Authorization", "Bearer "+config.Token)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, fmt.Errorf("authentication required or insufficient permissions")
	default:
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, body)
	}
}
