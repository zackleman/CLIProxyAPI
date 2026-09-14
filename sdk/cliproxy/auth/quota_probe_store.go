package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// quotaSidecarExt is the per-auth quota probe sidecar extension. It must stay
// distinct from ".json" (the auth file watcher and token store walk every
// *.json under the auth dir) and from ".cds" (the cooldown store deletes any
// unknown .cds file on save).
const quotaSidecarExt = ".quota"

type quotaProbeFile struct {
	Version   int         `json:"version"`
	AuthID    string      `json:"auth_id,omitempty"`
	Provider  string      `json:"provider,omitempty"`
	UpdatedAt time.Time   `json:"updated_at"`
	Probe     *QuotaProbe `json:"probe,omitempty"`
}

// fileQuotaProbeStore persists one .quota sidecar per auth mirroring the auth
// file's relative path, following the FileCooldownStateStore conventions.
type fileQuotaProbeStore struct {
	dir     string
	authDir string
}

func newFileQuotaProbeStore(dir, authDir string) *fileQuotaProbeStore {
	return &fileQuotaProbeStore{dir: strings.TrimSpace(dir), authDir: strings.TrimSpace(authDir)}
}

func (s *fileQuotaProbeStore) pathFor(auth *Auth) string {
	if s == nil || s.dir == "" || auth == nil {
		return ""
	}
	authID := strings.TrimSpace(auth.ID)
	if authID == "" {
		return ""
	}
	if authFile := cooldownAuthFile(auth); authFile != "" {
		if filepath.IsAbs(authFile) && s.authDir != "" {
			if rel, errRel := filepath.Rel(s.authDir, authFile); errRel == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				return filepath.Join(s.dir, quotaPathForRel(rel))
			}
		}
		if !filepath.IsAbs(authFile) {
			return filepath.Join(s.dir, quotaPathForRel(authFile))
		}
		return filepath.Join(s.dir, sanitizeQuotaFileName(filepath.Base(authFile)))
	}
	return filepath.Join(s.dir, sanitizeQuotaFileName(authID))
}

func quotaPathForRel(rel string) string {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return ""
	}
	dir := filepath.Dir(clean)
	base := sanitizeQuotaFileName(filepath.Base(clean))
	if base == "" {
		return ""
	}
	if dir == "." {
		return base
	}
	return filepath.Join(dir, base)
}

func sanitizeQuotaFileName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if ext := filepath.Ext(name); ext != "" {
		name = strings.TrimSuffix(name, ext)
	}
	name = cooldownFileNameUnsafe.ReplaceAllString(name, "_")
	name = strings.Trim(name, "._-")
	if name == "" {
		return ""
	}
	return name + quotaSidecarExt
}

// Save atomically writes the auth's probe beside the other auth state. A nil
// probe removes the sidecar.
func (s *fileQuotaProbeStore) Save(ctx context.Context, auth *Auth) error {
	if s == nil || s.dir == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if errCtx := ctx.Err(); errCtx != nil {
		return errCtx
	}
	path := s.pathFor(auth)
	if path == "" {
		return fmt.Errorf("quota probe path: missing auth identity")
	}
	if auth.Quota.Probe == nil {
		if errRemove := os.Remove(path); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
			return fmt.Errorf("remove quota probe %s: %w", path, errRemove)
		}
		return nil
	}
	envelope := quotaProbeFile{
		Version:   1,
		AuthID:    strings.TrimSpace(auth.ID),
		Provider:  strings.ToLower(strings.TrimSpace(auth.Provider)),
		UpdatedAt: time.Now().UTC(),
		Probe:     auth.Quota.Probe,
	}
	data, errMarshal := json.MarshalIndent(envelope, "", "  ")
	if errMarshal != nil {
		return fmt.Errorf("marshal quota probe: %w", errMarshal)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return fmt.Errorf("create quota probe directory: %w", errMkdir)
	}
	tmpFile, errCreate := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if errCreate != nil {
		return fmt.Errorf("create quota probe temp file: %w", errCreate)
	}
	tmp := tmpFile.Name()
	if _, errWrite := tmpFile.Write(data); errWrite != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write quota probe temp file: %w", errWrite)
	}
	if errClose := tmpFile.Close(); errClose != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close quota probe temp file: %w", errClose)
	}
	if errRename := os.Rename(tmp, path); errRename != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace quota probe file: %w", errRename)
	}
	return nil
}

// LoadAll reads every .quota sidecar keyed by auth ID. Stale content is kept:
// reset timestamps remain useful for ordering even after percent staleness.
func (s *fileQuotaProbeStore) LoadAll(ctx context.Context) map[string]*QuotaProbe {
	probes := make(map[string]*QuotaProbe)
	if s == nil || s.dir == "" {
		return probes
	}
	if ctx == nil {
		ctx = context.Background()
	}
	errWalk := filepath.WalkDir(s.dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if errCtx := ctx.Err(); errCtx != nil {
			return errCtx
		}
		if entry == nil || entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), quotaSidecarExt) {
			return nil
		}
		data, errRead := os.ReadFile(path)
		if errRead != nil {
			return nil //nolint:nilerr // unreadable sidecar: skip, a fresh poll will recreate it
		}
		var envelope quotaProbeFile
		if errUnmarshal := json.Unmarshal(data, &envelope); errUnmarshal != nil || envelope.Probe == nil {
			return nil //nolint:nilerr
		}
		authID := strings.TrimSpace(envelope.AuthID)
		if authID != "" {
			probes[authID] = envelope.Probe
		}
		return nil
	})
	if errWalk != nil && !errors.Is(errWalk, os.ErrNotExist) {
		// Missing directory is normal on first run; other errors leave the
		// probe cache empty and the poller will rebuild it.
		return probes
	}
	return probes
}
