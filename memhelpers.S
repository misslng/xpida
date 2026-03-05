/* Local memset/memcpy for KPM module.
 * Compiler-generated BL memset/memcpy has ±128MB range.
 * Providing local implementations avoids CALL26 relocation overflow.
 */

.global memset
.type memset, @function
memset:
    mov     x3, x0
    cbz     x2, 1f
0:  strb    w1, [x3], #1
    subs    x2, x2, #1
    b.ne    0b
1:  ret
.size memset, . - memset

.global memcpy
.type memcpy, @function
memcpy:
    mov     x3, x0
    cbz     x2, 1f
0:  ldrb    w4, [x1], #1
    strb    w4, [x3], #1
    subs    x2, x2, #1
    b.ne    0b
1:  ret
.size memcpy, . - memcpy
