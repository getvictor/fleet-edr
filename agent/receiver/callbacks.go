package receiver

// This file contains the //export functions that CGo exposes to C.
// They are called from the XPC bridge event handler via function pointers.

/*
#include <stddef.h>
#include <stdint.h>
*/
import "C"
import "unsafe"

//export bridgeOnEvent
func bridgeOnEvent(ctx unsafe.Pointer, data *C.uint8_t, length C.size_t) {
	id := int(uintptr(ctx))
	onEvent(id, unsafe.Pointer(data), int(length))
}

//export bridgeOnError
func bridgeOnError(ctx unsafe.Pointer, errorCode C.int) {
	id := int(uintptr(ctx))
	onError(id, int(errorCode))
}
