package narrow

// a // want "wrapped narrowly"
// b
// c
func A() {}

// Two-line block sits below the min-block floor so the analyzer leaves it untouched.
func B() {}

// d // want "wrapped narrowly"
// e
// f
// g
func C() {}
