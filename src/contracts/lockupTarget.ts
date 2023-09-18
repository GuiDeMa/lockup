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

export class LockupTarget extends SmartContract {

    @prop()
    target: ByteString // txid to lock to
  
    @prop()
    lockUntilHeight: bigint

    @prop()
    pkhash: PubKeyHash

    constructor(target: ByteString, pkhash: PubKeyHash, lockUntilHeight: bigint) {
        super(...arguments)
        assert(lockUntilHeight < 500000000, 'must use blockHeight locktime')
        this.target = target
        this.lockUntilHeight = lockUntilHeight
        this.pkhash = pkhash
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
            hash160(pubkey) == this.pkhash,
            'public key hashes are not equal'
        )
        // Check signature validity.
        assert(this.checkSig(sig, pubkey), 'signature check failed')
    }
}
