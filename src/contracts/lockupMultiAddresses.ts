import {
    method,
    prop,
    SmartContract,
    assert,
    PubKeyHash,
    Sig,
    PubKey,
    hash160,
} from 'scrypt-ts'

export class LockupMultiAddresses extends SmartContract {
    @prop()
    lockUntilHeight: bigint

    @prop()
    pkhashArray: HashSet<PubKeyHash>

    constructor(pkhashArray: HashSet<PubKeyHash>, lockUntilHeight: bigint) {
        super(...arguments)
        assert(lockUntilHeight < 500000000, 'must use blockHeight locktime')
        this.lockUntilHeight = lockUntilHeight
        this.pkhashArray = pkhashArray
    }

    @method()
    public redeem(sig: Sig, pubkey: PubKey) {
        assert(this.ctx.locktime < 500000000, 'must use blockHeight locktime')
        assert(this.ctx.sequence < 0xffffffff, 'must use sequence locktime')
        assert(
            this.ctx.locktime >= this.lockUntilHeight,
            'lockUntilHeight not reached'
        )
        assert(
          this.pkhashArray.has(hash160(pubkey)),
            'public key hash is not part of the receiving addresses'
        )
        // Check signature validity.
        assert(this.checkSig(sig, pubkey), 'signature check failed')
    }
}
