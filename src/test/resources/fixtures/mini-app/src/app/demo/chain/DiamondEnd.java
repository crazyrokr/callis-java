package demo.chain;

/**
 * Implements I01 directly and through I03: the walk reaches I01 twice,
 * exercising the seen-set duplicate skip (M3 branch coverage).
 */
public class DiamondEnd implements I01, I03 {
}
