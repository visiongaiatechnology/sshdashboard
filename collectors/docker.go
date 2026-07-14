// STATUS: DIAMANT VGT SUPREME
//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"sshdash/types"
	"sshdash/utils"
)

type rawDockerContainer struct {
	ID      string   `json:"Id"`
	Names   []string `json:"Names"`
	Image   string   `json:"Image"`
	Status  string   `json:"Status"`
	State   string   `json:"State"`
	Created int64    `json:"Created"`
}

func GetDockerState(ctx context.Context, wg *sync.WaitGroup, state *types.DockerState) {
	defer wg.Done()

	sockPath := "/var/run/docker.sock"
	if _, err := os.Stat(sockPath); os.IsNotExist(err) {
		state.SocketPresent = false
		state.Installed = IsProcessRunning("dockerd")
		return
	}

	state.SocketPresent = true
	state.Installed = true

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(dialCtx, "unix", sockPath)
			},
		},
		Timeout: 500 * time.Millisecond,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "http://unix/containers/json?all=1", nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	// Limit reader to 512KB to protect against rogue Unix Socket payload bombing
	limitReader := io.LimitReader(resp.Body, 512*1024)
	var rawContainers []rawDockerContainer
	if err := json.NewDecoder(limitReader).Decode(&rawContainers); err != nil {
		return
	}

	state.TotalContainers = len(rawContainers)
	runningCount := 0
	var containerEntries []types.ContainerEntry

	for _, c := range rawContainers {
		if c.State == "running" {
			runningCount++
		}

		cName := "unnamed"
		if len(c.Names) > 0 {
			cName = strings.TrimPrefix(c.Names[0], "/")
		}

		cID := c.ID
		if len(cID) > 12 {
			cID = cID[:12]
		}

		img := c.Image
		if len(img) > 24 {
			img = img[:24]
		}

		containerEntries = append(containerEntries, types.ContainerEntry{
			ID:     utils.SanitizeStr(cID),
			Names:  utils.SanitizeStr(cName),
			Image:  utils.SanitizeStr(img),
			Status: utils.SanitizeStr(c.Status),
			State:  utils.SanitizeStr(c.State),
		})
	}

	state.RunningContainers = runningCount
	if len(containerEntries) > 6 {
		state.Containers = containerEntries[:6]
	} else {
		state.Containers = containerEntries
	}
}
