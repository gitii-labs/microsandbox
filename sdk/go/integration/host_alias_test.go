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

// Documented slot-zero guest addresses, explicitly selected on each isolated guest stack.
// Gateways are discovered in the running guest rather than assumed from these values.
const hostAliasGuestIPv4 = "172.16.0.2"
const hostAliasGuestIPv6 = "fd42:6d73:62::2"

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
					Interface: &microsandbox.NetworkInterfaceOverrides{
						IPv4Address: hostAliasGuestIPv4,
						IPv6Address: hostAliasGuestIPv6,
					},
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
			network, err := sb.Shell(ctx, "command -v awk && command -v ip && command -v wget && ip addr show dev eth0 && ip -4 route show default && ip -6 route show default && cat /etc/hosts")
			if err != nil {
				t.Fatalf("inspect guest network: %v", err)
			}
			if !network.Success() {
				t.Fatalf("guest network inspection failed: stdout=%q stderr=%q", network.Stdout(), network.Stderr())
			}
			networkState := network.Stdout()
			for _, expected := range []string{"inet " + hostAliasGuestIPv4 + "/", "inet6 " + hostAliasGuestIPv6 + "/"} {
				if !strings.Contains(networkState, expected) {
					t.Fatalf("missing guest interface address %q: %s", expected, networkState)
				}
			}
			out, err := sb.Shell(ctx, "awk '$2 == \"host.microsandbox.internal\" {print $1}' /etc/hosts")
			if err != nil || !out.Success() {
				t.Fatalf("read gateway addresses: %v, %#v; guest network: %s", err, out, networkState)
			}
			gateways := strings.Fields(out.Stdout())
			if len(gateways) != 2 {
				t.Fatalf("expected both gateway families: %q; guest network: %s", out.Stdout(), networkState)
			}
			seen4, seen6 := false, false
			for _, gateway := range gateways {
				ip := net.ParseIP(gateway)
				if ip == nil {
					t.Fatalf("invalid gateway %q", gateway)
				}
				if !strings.Contains(networkState, "default via "+gateway+" ") {
					t.Fatalf("guest gateway route missing for %s: %s", gateway, networkState)
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
