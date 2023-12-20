package main

import (
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

	err = config.Validate()
	if err != nil {
		log.Fatal(err)
	}

	githubAPIToken, ok := os.LookupEnv("GITHUB_API_TOKEN")
	if !ok || githubAPIToken == "" {
		log.Fatal("GITHUB_API_TOKEN environment variable must be set and non-empty")
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
			missingLastRelease := false
			lastReleaseID, err := getLastReleaseID(config.DeployDir, target.Name)
			if err != nil {
				if os.IsNotExist(err) {
					missingLastRelease = true
				} else {
					log.Printf("%s: error getting last release ID: %v", target.Name, err)
					continue
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

			err = deployRelease(config.DeployDir, target.Name, releaseID, lastReleaseID, tarGzBytes)
			if err != nil {
				log.Printf("%s update failed: %v", target.Name, err)
				continue
			}
			log.Printf("%s: update successful", target.Name)
		}
		time.Sleep(time.Duration(config.UpdateInterval) * time.Second)
	}
}

func getReleaseDir(deployDir, targetName, releaseID string) string {
	return filepath.Join(deployDir, targetName+"-"+releaseID)
}

func getReleaseSymlink(deployDir, targetName string) string {
	return filepath.Join(deployDir, targetName)
}

func getLastReleaseID(deployDir, targetName string) (string, error) {
	lastReleaseSymlink := getReleaseSymlink(deployDir, targetName)
	fi, err := os.Lstat(lastReleaseSymlink)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("%s is not a symlink", lastReleaseSymlink)
	}

	lastReleaseDir, err := os.Readlink(lastReleaseSymlink)
	if err != nil {
		return "", err
	}
	split := strings.Split(filepath.Base(lastReleaseDir), "-")
	if len(split) != 2 {
		return "", fmt.Errorf("invalid last release directory name: %s", lastReleaseDir)
	}
	return split[1], nil
}

func downloadReleaseAssets(target *Target, release *github.RepositoryRelease) (tarGzBytes, sigBytes []byte, err error) {
	if len(release.Assets) < 2 {
		err = fmt.Errorf("release needs at least 2 assets (have %v)", len(release.Assets))
		return
	}

	const tarGzRegexFmt = `^%s-[\w.]+\.tar\.gz$`
	const sigRegexFmt = `^%s-[\w.]+\.minisig$`
	tarGzRegex := regexp.MustCompile(fmt.Sprintf(tarGzRegexFmt, target.Repo))
	sigRegex := regexp.MustCompile(fmt.Sprintf(sigRegexFmt, target.Repo))

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

func deployRelease(deployDir, targetName, releaseID, lastReleaseID string, tarGzBytes []byte) error {
	releaseDir := getReleaseDir(deployDir, targetName, releaseID)
	if err := os.Mkdir(releaseDir, 0755); err != nil {
		return err
	}
	if err := extractTarGz(tarGzBytes, releaseDir, 1); err != nil {
		return err
	}

	releaseSymlink := getReleaseSymlink(deployDir, targetName)
	if err := os.Symlink(releaseDir, releaseSymlink+".tmp"); err != nil {
		return err
	}
	if err := os.Rename(releaseSymlink+".tmp", releaseSymlink); err != nil {
		return err
	}

	// clean up last release dir
	return os.RemoveAll(getReleaseDir(deployDir, targetName, lastReleaseID))
}
