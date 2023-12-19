//go:debug tarinsecurepath=0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v57/github"
	"github.com/jedisct1/go-minisign"
)

type Target struct {
	Name  string
	Owner string
	Repo  string
}

type Config struct {
	MetadataDir                     string    `json:"metadata_dir"`
	DeployDir                       string    `json:"deploy_dir"`
	Targets                         []*Target `json:"targets"`
	PublicSigningKey                string    `json:"public_signing_key"`
	UnsafeSkipSignatureVerification bool      `json:"unsafe_skip_signature_verification"`
	UpdateInterval                  int       `json:"update_interval"`
}

func main() {
	configFile := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	b, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	config := Config{}
	err = json.Unmarshal(b, &config)
	if err != nil {
		log.Fatal(err)
	}

	err = validateConfig(&config)
	if err != nil {
		log.Fatal(err)
	}

	err = os.MkdirAll(config.MetadataDir, 0750)
	if err != nil {
		log.Fatal(err)
	}

	githubAPIToken, ok := os.LookupEnv("GITHUB_API_TOKEN")
	if !ok {
		log.Fatal("GITHUB_API_TOKEN environment variable must be set")
	}
	client := github.NewClient(nil).WithAuthToken(githubAPIToken)

	for {
		for _, target := range config.Targets {
			log.Printf("%s: checking for update...", target.Name)

			ctx := context.Background()
			release, _, err := client.Repositories.GetLatestRelease(ctx, target.Owner, target.Repo)
			if err != nil {
				log.Printf("%s: %v", target.Name, err)
				continue
			}

			releaseID := strconv.FormatInt(*release.ID, 10)
			lastReleaseFile := filepath.Join(config.MetadataDir, fmt.Sprintf("%v_last_release_id", target.Name))
			missingLastRelease := false
			lastReleaseID, err := os.ReadFile(lastReleaseFile)
			if err != nil {
				if os.IsNotExist(err) {
					missingLastRelease = true
				} else {
					log.Fatal(err)
				}
			}
			if !missingLastRelease && string(lastReleaseID) == releaseID {
				log.Printf("%s: already at latest release", target.Name)
				continue
			}

			log.Printf("%s: update found", target.Name)
			tarGzBytes, sigBytes, err := downloadReleaseAssets(target, release)
			if err != nil {
				log.Printf("%s: update failed: %v", target.Name, err)
				continue
			}

			if !config.UnsafeSkipSignatureVerification {
				ok, err := verifySignature(config.PublicSigningKey, tarGzBytes, sigBytes)
				if !ok {
					log.Printf("%s: update failed: %v", target.Name, err)
					continue
				}
			} else {
				log.Printf("%s: skipping signature verification!", target.Name)
			}

			err = deploy(config.DeployDir, target.Name, releaseID, tarGzBytes, lastReleaseFile, string(lastReleaseID))
			if err != nil {
				log.Printf("%s update failed: %v", target.Name, err)
				continue
			}
			log.Printf("%s: update successful", target.Name)
		}
		time.Sleep(time.Duration(config.UpdateInterval) * time.Second)
	}
}

func validateConfig(config *Config) error {
	if config.MetadataDir == "" {
		return fmt.Errorf("metadata directory must be set")
	}
	if config.DeployDir == "" {
		return fmt.Errorf("deploy directory must be set")
	}
	if config.UpdateInterval <= 0 {
		return fmt.Errorf("update interval must be >0")
	}
	if !config.UnsafeSkipSignatureVerification && config.PublicSigningKey == "" {
		return fmt.Errorf("public signing key must be set if signature verification is enabled")
	}
	if len(config.Targets) == 0 {
		return fmt.Errorf("at least one target must be set")
	}
	return nil
}

func downloadReleaseAssets(target *Target, release *github.RepositoryRelease) (tarGzBytes, sigBytes []byte, err error) {
	if len(release.Assets) < 2 {
		err = fmt.Errorf("release needs at least 2 assets (have %v)", len(release.Assets))
		return
	}

	const tarGzRegexFmt = `^%s-[\w.]+\.tar\.gz$`
	const sigRegexFmt = `^%s-[\w.]+\.minisig$`
	tarGzRegex := regexp.MustCompile(fmt.Sprintf(tarGzRegexFmt, target.Name))
	sigRegex := regexp.MustCompile(fmt.Sprintf(sigRegexFmt, target.Name))

	if !(tarGzRegex.MatchString(*release.Assets[0].Name)) {
		err = fmt.Errorf("first asset doesn't have expected name (%v)", *release.Assets[0].Name)
		return
	}
	if !(sigRegex.MatchString(*release.Assets[1].Name)) {
		err = fmt.Errorf("second asset doesn't have expected name (%v)", *release.Assets[1].Name)
		return
	}

	tarGzDownloadUrl := release.Assets[0].GetBrowserDownloadURL()
	if err = validateAssetURL(tarGzDownloadUrl); err != nil {
		err = fmt.Errorf("tar.gz URL validation failed: %v", err)
		return
	}
	sigDownloadURL := release.Assets[1].GetBrowserDownloadURL()
	if err = validateAssetURL(sigDownloadURL); err != nil {
		err = fmt.Errorf("signature URL validation failed: %v", err)
		return
	}

	tarGzBytes, err = downloadAsset(tarGzDownloadUrl)
	if err != nil {
		err = fmt.Errorf("tar.gz download failed: %v", err)
		return
	}

	sigBytes, err = downloadAsset(sigDownloadURL)
	if err != nil {
		err = fmt.Errorf("signature download failed: %v", err)
		return
	}
	return
}

func validateAssetURL(assetUrl string) error {
	parsedURL, err := url.Parse(assetUrl)
	if err != nil {
		return err
	}
	if parsedURL.Hostname() != "github.com" {
		return fmt.Errorf("asset has non-GitHub URL (%v)", assetUrl)
	}
	return nil
}

func downloadAsset(assetUrl string) ([]byte, error) {
	resp, err := http.Get(assetUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func verifySignature(publicSigningKey string, tarGzBytes, sigBytes []byte) (bool, error) {
	pk, err := minisign.DecodePublicKey(publicSigningKey)
	if err != nil {
		return false, err
	}
	sig, err := minisign.DecodeSignature(string(sigBytes))
	if err != nil {
		return false, err
	}
	return pk.Verify(tarGzBytes, sig)
}

func deploy(deployDir, targetName, releaseID string, tarGzBytes []byte, lastReleaseFile, lastReleaseID string) error {
	extractDir := filepath.Join(deployDir, targetName) + "-" + releaseID
	if err := os.Mkdir(extractDir, 0755); err != nil {
		return err
	}
	if err := extractTarGz(tarGzBytes, extractDir, 1); err != nil {
		return err
	}
	if err := os.Symlink(extractDir, extractDir+".tmp"); err != nil {
		return err
	}
	if err := os.Rename(extractDir+".tmp", filepath.Join(deployDir, targetName)); err != nil {
		return err
	}
	if err := os.WriteFile(lastReleaseFile, []byte(releaseID), 0640); err != nil {
		return err
	}

	// clean up old release dir
	return os.RemoveAll(filepath.Join(deployDir, targetName) + "-" + lastReleaseID)
}

func extractTarGz(tarGzData []byte, destination string, stripComponents int) error {
	buf := bytes.NewBuffer(tarGzData)
	gzipReader, err := gzip.NewReader(buf)
	if err != nil {
		return err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Skip pax_global_header entries
		if header.Name == "pax_global_header" {
			continue
		}

		// Calculate the target path by stripping components
		target := header.Name
		if stripComponents > 0 {
			components := strings.SplitN(target, string(filepath.Separator), stripComponents+1)
			if len(components) > stripComponents {
				target = strings.Join(components[stripComponents:], string(filepath.Separator))
			} else {
				target = ""
			}
		}

		// Get the full path for the file
		target = filepath.Join(destination, target)

		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory if it doesn't exist
			if err := os.MkdirAll(target, os.ModePerm); err != nil {
				return err
			}

		case tar.TypeReg:
			// Create file
			file, err := os.Create(target)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(file, tarReader); err != nil {
				return err
			}

		default:
			return fmt.Errorf("unsupported file type: %v in %v", header.Typeflag, header.Name)
		}
	}

	return nil
}
