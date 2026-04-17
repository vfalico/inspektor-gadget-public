module nvidia_trace_errors

go 1.25.7

require (
	// Version doesn't matter because of the replace directive below.
	github.com/inspektor-gadget/inspektor-gadget v0.0.0
)

// Only needed by in-tree gadgets
replace github.com/inspektor-gadget/inspektor-gadget => ../../../
