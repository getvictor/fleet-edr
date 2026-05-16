package narrow

// a // want "wrapped narrowly"
// b
// c
var A = 1

// Single-line block is below the min-block floor so the analyzer leaves it untouched.
var B = 1

// d // want "wrapped narrowly"
// e
// f
// g
var C = 1
