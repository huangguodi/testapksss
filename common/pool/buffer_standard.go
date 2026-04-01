package pool

const (
	// RelayBufferSize using for tcp
	// io.Copy default buffer size is 32 KiB
	// iOS optimization: reduce to 16 KiB to save memory
	RelayBufferSize = 16 * 1024

	// UDPBufferSize using for udp
	// Most UDPs are smaller than the MTU, and the TUN's MTU
	// set to 9000, so the UDP Buffer size set to 16Kib
	// iOS optimization: reduce to 8 KiB
	UDPBufferSize = 8 * 1024
)
