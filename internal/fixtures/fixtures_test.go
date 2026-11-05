package fixtures

import (
	"os/exec"
	"strings"
	"testing"
)

// TestServerDoesNotLinkTestCode keeps mock providers and test accounts out of the server binary.
func TestServerDoesNotLinkTestCode(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/teal-mongoose/auth-mcp/cmd/auth-mcp").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}

	for _, forbidden := range []string{
		"github.com/teal-mongoose/auth-mcp/internal/fixtures",
		"github.com/teal-mongoose/auth-mcp/internal/mockidp",
		"github.com/teal-mongoose/auth-mcp/internal/seed",
		"github.com/oauth2-proxy/mockoidc",
	} {
		for _, dep := range strings.Fields(string(out)) {
			if dep == forbidden {
				t.Errorf("cmd/auth-mcp depends on %s", forbidden)
			}
		}
	}
}
