
package libbpfgo

/*
#include <stdint.h>
*/
import "C"

import "unsafe"

//export perfCallback
func perfCallback(ctx C.uintptr_t, cpu C.int, data unsafe.Pointer, size C.uint32_t) {
    eventChannels[uintptr(ctx)] <- C.GoBytes(data, C.int(size))
}

//export perfLostCallback
func perfLostCallback(ctx C.uintptr_t, cpu C.int, cnt C.uint64_t) {
    lostChan := lostChannels[uintptr(ctx)]
    if lostChan != nil {
        lostChan <- uint64(cnt)
    }
}
