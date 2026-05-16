// Filled covers the positive case: a multi-line // block whose longest line clears the 120-column floor does not trip the
// analyzer. The second line here is shorter; only the LONGEST line needs to reach the threshold, and that property is what
// shields this fixture from firing the linter, which is exactly the analyzer behaviour we are pinning.
package filled
