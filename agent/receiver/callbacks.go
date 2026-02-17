package receiver

// This file contains the //export functions that CGo exposes to C.
// They are called by bridgeOnEvent/bridgeOnError in callbacks.c.

/*
#include <stddef.h>
#include <stdint.h>
*/
import "C"
import "unsafe"

//export bridgeOnEvent
func bridgeOnEvent(_ unsafe.Pointer, data *C.uint8_t, length C.size_t) {
	onEvent(unsafe.Pointer(data), int(length))
}

//export bridgeOnError
func bridgeOnError(_ unsafe.Pointer, errorCode C.int) {
	onError(int(errorCode))
}
