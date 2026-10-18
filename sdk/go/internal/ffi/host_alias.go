package ffi

import "fmt"

// Validate before crossing the native boundary: older libraries ignore unknown JSON fields.
func validateHostAliasIPv4Ports(ports []uint16, supported bool) error {
	for _, port := range ports {
		if port == 0 {
			return fmt.Errorf("host-alias IPv4 ports must be between 1 and 65535")
		}
	}
	if len(ports) > 0 && !supported {
		return &Error{Kind: KindUnsupportedOperation, Message: "native SDK does not support port-scoped host-alias IPv4 targets; update the native SDK"}
	}
	return nil
}
