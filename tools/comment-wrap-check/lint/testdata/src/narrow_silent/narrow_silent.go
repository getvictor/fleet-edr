// Same narrow content as testdata/src/narrow but with NO analysistest annotations. Used by TestCustomSettings to verify
// that a tighter MinLineLen actually silences the analyzer: under default settings these blocks would fire, so a clean
// run here is only possible if the custom Settings argument is being honoured.
package narrow_silent

// a
// b
// c
var A = 1

// d
// e
// f
// g
var C = 1
