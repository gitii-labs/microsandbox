//go:build integration && microsandbox_ffi_path

package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func TestHostAliasIPv4PortsBothGuestFamilies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "explicit ipv4 target")
	}))
	t.Cleanup(server.Close)
	address := server.Listener.Addr().(*net.TCPAddr)
	if !address.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("fixture must listen only on 127.0.0.1, got %v", address)
	}
	for _, allow := range []bool{true, false} {
		t.Run(fmt.Sprintf("allow=%v", allow), func(t *testing.T) {
			ctx := integrationCtx(t)
			action := microsandbox.PolicyActionDeny
			if allow {
				action = microsandbox.PolicyActionAllow
			}
			sb, err := microsandbox.CreateSandbox(ctx, uniqueIntegrationName(t, "host-alias-v4"),
				microsandbox.WithImage(goIntegrationImage),
				microsandbox.WithNetwork(&microsandbox.NetworkConfig{
					HostAliasIPv4Ports: []uint16{uint16(address.Port)},
					IPv4Pool:           "172.16.0.0/12", IPv6Pool: "fd42:6d73:62::/48",
					DefaultEgress: microsandbox.PolicyActionDeny,
					Rules: []microsandbox.PolicyRule{{
						Action: microsandbox.PolicyActionDeny, Direction: microsandbox.PolicyDirectionEgress,
						Destination: "127.0.0.1/32", Protocol: microsandbox.PolicyProtocolTCP,
					}, {
						Action: action, Direction: microsandbox.PolicyDirectionEgress,
						Destination: "host", Protocol: microsandbox.PolicyProtocolTCP,
					}},
				}),
			)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			t.Cleanup(func() {
				stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := sb.Stop(stopCtx); err != nil {
					t.Error(err)
				}
				if err := sb.Close(); err != nil {
					t.Error(err)
				}
			})
			out, err := sb.Shell(ctx, "awk '$2 == \"host.microsandbox.internal\" {print $1}' /etc/hosts")
			if err != nil || !out.Success() {
				t.Fatalf("read gateway addresses: %v, %#v", err, out)
			}
			gateways := strings.Fields(out.Stdout())
			if len(gateways) != 2 {
				t.Fatalf("expected both gateway families: %q", out.Stdout())
			}
			seen4, seen6 := false, false
			for _, gateway := range gateways {
				ip := net.ParseIP(gateway)
				if ip == nil {
					t.Fatalf("invalid gateway %q", gateway)
				}
				seen4 = seen4 || ip.To4() != nil
				seen6 = seen6 || ip.To4() == nil
				url := "http://" + net.JoinHostPort(gateway, fmt.Sprint(address.Port)) + "/"
				result, err := sb.Shell(ctx, "wget -qO- --timeout=5 '"+url+"'")
				if err != nil {
					t.Fatalf("request %s: %v", gateway, err)
				}
				if result.Success() != allow {
					t.Fatalf("allow=%v gateway=%s stdout=%q stderr=%q", allow, gateway, result.Stdout(), result.Stderr())
				}
				if allow && result.Stdout() != "explicit ipv4 target" {
					t.Fatalf("wrong service: %q", result.Stdout())
				}
			}
			if !seen4 || !seen6 {
				t.Fatalf("both families required, got %v", gateways)
			}
		})
	}
}
