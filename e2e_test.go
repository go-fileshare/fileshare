//go:build !nosmb && !nowebdav

package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// One image, two protocols, at the same time.
//
// This is the product's whole claim: the same bytes, reachable two ways at
// once, with no interference. It runs under -race in CI, where the shared lock
// (see lockedfs.go) is the thing being exercised -- though the honest note is
// that an unwrapped fat32 driver does not race today either, so this test
// demonstrates that the two protocols WORK together rather than that the lock
// is load-bearing for this driver.
func TestOneImageTwoProtocolsAtOnce(t *testing.T) {
	dir := t.TempDir()
	img := image(t, dir, "shared.img", map[string]string{
		"/greeting.txt": "hello from one image",
		"/blob.bin":     strings.Repeat("go-fileshare ", 4096), // 52 KiB
	})
	r := start(t, configFor(t, dir, fmt.Sprintf(`
share "shared" {
  image = %q
}`, hclPath(img))))

	smbFS := mountSMB(t, r, "alice", "hunter2", "shared")

	// Twenty rounds of each, concurrently, over the same driver. Under -race
	// this is where a missing lock is a finding rather than an opinion.
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := range 20 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			got, err := smbFS.ReadFile("greeting.txt")
			if err != nil {
				errs <- fmt.Errorf("smb read: %w", err)
				return
			}
			if string(got) != "hello from one image" {
				errs <- fmt.Errorf("smb read gave %q", got)
			}
		}()
		go func() {
			defer wg.Done()
			body, err := webdavGet(r, "alice", "hunter2", "/shared/blob.bin")
			if err != nil {
				errs <- fmt.Errorf("webdav read: %w", err)
				return
			}
			if len(body) != 13*4096 {
				errs <- fmt.Errorf("webdav read gave %d bytes, want %d", len(body), 13*4096)
			}
		}()
		_ = i
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// What each protocol makes of the same access rules.
func TestTheSameRulesThroughEveryProtocol(t *testing.T) {
	dir := t.TempDir()
	img := image(t, dir, "photos.img", map[string]string{"/greeting.txt": "hello"})
	open := image(t, dir, "open.img", map[string]string{"/greeting.txt": "everyone"})
	r := start(t, configFor(t, dir, fmt.Sprintf(`
share "photos" {
  image   = %q
  allow   = ["alice", "bob"]
  writers = ["alice"]
}

share "open" {
  image = %q
}`, hclPath(img), hclPath(open))))

	t.Run("smb: alice writes, bob does not", func(t *testing.T) {
		as := mountSMB(t, r, "alice", "hunter2", "photos")
		if err := as.WriteFile("fromalice.txt", []byte("mine"), 0o644); err != nil {
			t.Errorf("alice could not write: %v", err)
		}
		bs := mountSMB(t, r, "bob", "swordfish", "photos")
		if got, err := bs.ReadFile("greeting.txt"); err != nil || string(got) != "hello" {
			t.Errorf("bob read %q, %v", got, err)
		}
		if err := bs.WriteFile("frombob.txt", []byte("nope"), 0o644); err == nil {
			t.Error("bob wrote to a share he may only read")
		}
	})

	t.Run("webdav: the same answers", func(t *testing.T) {
		if _, err := webdavGet(r, "alice", "hunter2", "/photos/greeting.txt"); err != nil {
			t.Errorf("alice: %v", err)
		}
		if err := webdavPut(r, "alice", "hunter2", "/photos/fromalice2.txt", "mine"); err != nil {
			t.Errorf("alice could not write: %v", err)
		}
		if err := webdavPut(r, "bob", "swordfish", "/photos/frombob.txt", "nope"); err == nil {
			t.Error("bob wrote to a share he may only read")
		}
		// A password that is wrong is a 401, not a 404: the share is there.
		if _, err := webdavGet(r, "alice", "wrong", "/photos/greeting.txt"); err == nil ||
			!strings.Contains(err.Error(), "401") {
			t.Errorf("a wrong password gave %v", err)
		}
	})

	t.Run("what was announced names every protocol this binary has", func(t *testing.T) {
		said := r.out.String()
		for _, p := range protocols {
			if !strings.Contains(said, p.name) {
				t.Errorf("the announcement does not mention %q:\n%s", p.name, said)
			}
		}
	})
}

func webdavGet(r *running, user, password, path string) ([]byte, error) {
	req, _ := http.NewRequest(http.MethodGet, "http://"+r.addrs["webdav"]+path, nil)
	req.SetBasicAuth(user, password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %d", path, res.StatusCode)
	}
	return body, nil
}

func webdavPut(r *running, user, password, path, body string) error {
	req, _ := http.NewRequest(http.MethodPut, "http://"+r.addrs["webdav"]+path, strings.NewReader(body))
	req.SetBasicAuth(user, password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	io.Copy(io.Discard, res.Body)
	if res.StatusCode >= 300 {
		return fmt.Errorf("%s: %d", path, res.StatusCode)
	}
	return nil
}
