package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestCodexWebsocketCancellationDoesNotContaminateNextRequest(t *testing.T) {
	for _, mode := range []string{"stream", "buffered-stream", "non-stream"} {
		t.Run(mode, func(t *testing.T) {
			var connections atomic.Int32
			firstStarted := make(chan struct{})
			upgrader := websocket.Upgrader{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, errUpgrade := upgrader.Upgrade(w, r, nil)
				if errUpgrade != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				connection := connections.Add(1)
				if _, _, errRead := conn.ReadMessage(); errRead != nil {
					return
				}
				if connection == 1 {
					_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"resp_old"}}`))
					close(firstStarted)
					// A canceled generation is still running upstream. If its socket is
					// reused, the late completion belongs to the previous request.
					if _, _, errRead := conn.ReadMessage(); errRead == nil {
						_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"resp_old","output":[]}}`))
					}
					return
				}
				_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"resp_new","output":[]}}`))
			}))
			defer server.Close()

			exec := NewCodexWebsocketsExecutor(&config.Config{
				SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll},
				Codex:     config.CodexConfig{StreamBootstrapBuffering: mode == "buffered-stream"},
			})
			defer exec.CloseExecutionSession(t.Name())
			auth := &cliproxyauth.Auth{ID: "cancellation-test", Provider: "codex", Attributes: map[string]string{"api_key": "test-placeholder", "base_url": server.URL}}
			opts := cliproxyexecutor.Options{
				SourceFormat:   sdktranslator.FormatOpenAIResponse,
				ResponseFormat: sdktranslator.FormatOpenAIResponse,
				Metadata:       map[string]any{cliproxyexecutor.ExecutionSessionMetadataKey: t.Name()},
			}
			req := cliproxyexecutor.Request{Model: "gpt-5.4", Payload: []byte(`{"model":"gpt-5.4","input":[{"role":"user","content":"hello"}]}`)}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			firstFinished := make(chan struct{})
			go func() {
				defer close(firstFinished)
				if mode == "non-stream" {
					_, _ = exec.Execute(ctx, auth, req, opts)
					return
				}
				result, errExecute := exec.ExecuteStream(ctx, auth, req, opts)
				if errExecute == nil {
					for range result.Chunks {
					}
				}
			}()
			select {
			case <-firstStarted:
			case <-ctx.Done():
				t.Fatal("first request did not reach upstream")
			}
			cancel()
			select {
			case <-firstFinished:
			case <-time.After(5 * time.Second):
				t.Fatal("canceled request did not finish")
			}

			ctxNext, cancelNext := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelNext()
			result, errExecute := exec.ExecuteStream(ctxNext, auth, req, opts)
			if errExecute != nil {
				t.Fatal(errExecute)
			}
			var output strings.Builder
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					t.Fatal(chunk.Err)
				}
				output.Write(chunk.Payload)
			}
			if strings.Contains(output.String(), "resp_old") || !strings.Contains(output.String(), "resp_new") {
				t.Fatalf("next request received the canceled response: %s", output.String())
			}
			if got := connections.Load(); got != 2 {
				t.Fatalf("connections = %d, want a fresh connection after cancellation", got)
			}
		})
	}
}

func TestCodexWebsocketCompletedStreamsReuseConnection(t *testing.T) {
	var connections atomic.Int32
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := upgrader.Upgrade(w, r, nil)
		if errUpgrade != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		connections.Add(1)
		for {
			if _, _, errRead := conn.ReadMessage(); errRead != nil {
				return
			}
			if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"resp_complete","output":[]}}`)); errWrite != nil {
				return
			}
		}
	}))
	defer server.Close()
	exec := NewCodexWebsocketsExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
	defer exec.CloseExecutionSession(t.Name())
	auth := &cliproxyauth.Auth{ID: "reuse-test", Provider: "codex", Attributes: map[string]string{"api_key": "test-placeholder", "base_url": server.URL}}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAIResponse, ResponseFormat: sdktranslator.FormatOpenAIResponse,
		Metadata: map[string]any{cliproxyexecutor.ExecutionSessionMetadataKey: t.Name()},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 2 {
		result, errExecute := exec.ExecuteStream(ctx, auth, cliproxyexecutor.Request{Model: "gpt-5.4", Payload: []byte(`{"model":"gpt-5.4","input":[]}`)}, opts)
		if errExecute != nil {
			t.Fatal(errExecute)
		}
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				t.Fatal(chunk.Err)
			}
		}
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("connections = %d, want one reused connection", got)
	}
}
