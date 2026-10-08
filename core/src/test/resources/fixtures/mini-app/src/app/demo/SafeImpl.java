package demo;

import stublib.Stub;

/** M7b SPARK fixture: the only PIface implementation PointerDemo instantiates (calls safe()). */
public class SafeImpl implements PIface {

    @Override
    public void op() {
        new Stub().safe();
    }
}
