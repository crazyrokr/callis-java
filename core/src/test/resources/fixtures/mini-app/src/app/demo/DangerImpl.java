package demo;

import stublib.Stub;

/**
 * M7b SPARK fixture: never instantiated by PointerDemo. RTA type-based
 * expansion keeps op() (and the danger() call inside) in the graph -
 * the false positive SPARK is built to remove.
 */
public class DangerImpl implements PIface {

    @Override
    public void op() {
        new Stub().danger();
    }
}
