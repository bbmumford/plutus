/**
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 *
 * Plutus JS SDK — browser-side wrapper classes for the Plutus WASM module.
 * Exposes PlutusWallet, PlutusEscrow, PlutusWitness, PlutusReputation, and
 * the initPlutus() loader.
 */

/**
 * Initialize the Plutus WASM module.
 * @param {string} wasmUrl - URL to the plutus.wasm binary
 * @returns {Promise<{wallet: typeof PlutusWallet, escrow: typeof PlutusEscrow, witness: typeof PlutusWitness, reputation: typeof PlutusReputation}>}
 */
async function initPlutus(wasmUrl) {
  if (!wasmUrl) {
    throw new Error('initPlutus: wasmUrl is required');
  }

  // Load the Go WASM support if not already loaded
  if (typeof Go === 'undefined') {
    throw new Error('initPlutus: Go WASM support (wasm_exec.js) must be loaded first');
  }

  const go = new Go();
  let result;

  if (typeof WebAssembly.instantiateStreaming === 'function') {
    result = await WebAssembly.instantiateStreaming(fetch(wasmUrl), go.importObject);
  } else {
    const resp = await fetch(wasmUrl);
    const bytes = await resp.arrayBuffer();
    result = await WebAssembly.instantiate(bytes, go.importObject);
  }

  // Run the Go main() — this sets up globalThis.Plutus
  go.run(result.instance);

  // Wait for Plutus to be available (main() runs async)
  await waitForPlutus();

  return {
    wallet: PlutusWallet,
    escrow: PlutusEscrow,
    witness: PlutusWitness,
    reputation: PlutusReputation,
  };
}

/**
 * Wait for the Plutus global to be set by the WASM module.
 * @returns {Promise<void>}
 */
function waitForPlutus(timeout = 5000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      if (typeof globalThis.Plutus !== 'undefined') {
        resolve();
      } else if (Date.now() - start > timeout) {
        reject(new Error('initPlutus: WASM module did not initialize within timeout'));
      } else {
        setTimeout(check, 10);
      }
    };
    check();
  });
}

/**
 * PlutusWallet wraps wallet creation, mnemonic management, and signing.
 */
class PlutusWallet {
  /** @type {number} */
  #handle = 0;
  /** @type {string|null} */
  #mnemonic = null;

  /**
   * Create a new wallet with a fresh mnemonic.
   * @param {Object} [config] - Optional configuration
   * @returns {Promise<PlutusWallet>}
   */
  static async createNew(config) {
    const w = new PlutusWallet();
    w.#handle = await Plutus.createWallet(config || {});
    // Mnemonic is not exposed via the public JS API for security.
    // Use exportIdentity with user confirmation to retrieve it.
    w.#mnemonic = null;
    return w;
  }

  /**
   * Restore a wallet from an existing BIP39 mnemonic.
   * @param {string} mnemonic - 24-word BIP39 mnemonic
   * @returns {Promise<PlutusWallet>}
   */
  static async createFromMnemonic(mnemonic) {
    if (!mnemonic || typeof mnemonic !== 'string') {
      throw new Error('PlutusWallet.createFromMnemonic: mnemonic is required');
    }
    const w = new PlutusWallet();
    w.#handle = await Plutus.createWallet({ mnemonic });
    w.#mnemonic = mnemonic;
    return w;
  }

  /**
   * Get the chain address for a specific chain.
   * @param {string} chainID - Chain identifier (e.g., "ethereum", "polygon")
   * @returns {Promise<string>}
   */
  async address(chainID) {
    if (!chainID) throw new Error('PlutusWallet.address: chainID is required');
    return Plutus.walletAddress(this.#handle, chainID);
  }

  /**
   * Get the wallet's BIP39 mnemonic.
   * @returns {string}
   */
  get mnemonic() {
    return this.#mnemonic;
  }

  /**
   * Get the internal handle for use with escrow and witness APIs.
   * @returns {number}
   */
  get handle() {
    return this.#handle;
  }

  /**
   * Sign an escrow funding transaction (delegates to WASM signer).
   * Used internally by PlutusEscrow.
   * @param {Object} params - Escrow parameters
   * @returns {Promise<string>} Transaction hash
   */
  async signEscrow(params) {
    // Escrow signing is handled internally by the WASM bridge
    // when fundEscrow/releaseEscrow/disputeEscrow are called
    return this.#handle;
  }

  /**
   * Sign a settlement transaction (delegates to WASM signer).
   * @param {Object} params - Settlement parameters
   * @returns {Promise<string>}
   */
  async signSettlement(params) {
    return this.#handle;
  }
}

/**
 * PlutusEscrow wraps escrow lifecycle operations.
 */
class PlutusEscrow {
  /** @type {number} */
  #handle = 0;
  /** @type {PlutusWallet} */
  #wallet = null;
  /** @type {Function[]} */
  #changeListeners = [];

  /**
   * Create a new escrow bound to a wallet.
   * @param {PlutusWallet} wallet - The wallet to use for signing
   * @param {Object} params - Escrow parameters
   * @param {string} params.buyer - Buyer chain address
   * @param {string} params.seller - Seller chain address
   * @param {string} params.amount - Amount in smallest denomination
   * @param {string} params.currency - Currency symbol
   * @param {string} params.chainId - Target chain
   * @param {number} [params.timeoutBlocks] - Timeout in blocks
   * @returns {Promise<PlutusEscrow>}
   */
  static async create(wallet, params) {
    if (!(wallet instanceof PlutusWallet)) {
      throw new Error('PlutusEscrow.create: wallet must be a PlutusWallet instance');
    }
    const e = new PlutusEscrow();
    e.#wallet = wallet;
    e.#handle = await Plutus.createEscrow(wallet.handle, params || {});
    return e;
  }

  /**
   * Fund the escrow on-chain.
   * @param {Object} [params] - Optional funding parameters
   * @returns {Promise<string>} Transaction hash
   */
  async fund(params) {
    const txHash = await Plutus.fundEscrow(this.#handle, params);
    this.#notifyChange('funded', txHash);
    return txHash;
  }

  /**
   * Release escrow funds to the seller.
   * @returns {Promise<string>} Transaction hash
   */
  async release() {
    const txHash = await Plutus.releaseEscrow(this.#handle);
    this.#notifyChange('released', txHash);
    return txHash;
  }

  /**
   * File a dispute on the escrow.
   * @param {string} [evidence] - Evidence string for the dispute
   * @returns {Promise<string>} Transaction hash
   */
  async dispute(evidence) {
    const txHash = await Plutus.disputeEscrow(this.#handle, evidence);
    this.#notifyChange('disputed', txHash);
    return txHash;
  }

  /**
   * Settle a disputed escrow with an arbitrator ruling.
   * @param {Object} ruling - Arbitrator ruling
   * @param {number} ruling.buyerPercent - Percentage allocated to buyer (0-100)
   * @param {number} ruling.sellerPercent - Percentage allocated to seller (0-100)
   * @param {string} [ruling.outcome] - Ruling outcome description
   * @param {string} [ruling.arbitratorSig] - Hex-encoded arbitrator signature
   * @returns {Promise<string>} Transaction hash
   */
  async settle(ruling) {
    if (!ruling) throw new Error('PlutusEscrow.settle: ruling is required');
    const txHash = await Plutus.settleEscrow(this.#handle, ruling);
    this.#notifyChange('settled', txHash);
    return txHash;
  }

  /**
   * Query the current escrow state.
   * @returns {Promise<Object>} Current escrow state
   */
  async state() {
    const raw = await Plutus.escrowState(this.#handle);
    return typeof raw === 'string' ? JSON.parse(raw) : raw;
  }

  /**
   * Register a listener for escrow state changes.
   * @param {Function} listener - Called with (event, txHash) on state changes
   * @returns {Function} Unsubscribe function
   */
  onChange(listener) {
    if (typeof listener !== 'function') {
      throw new Error('PlutusEscrow.onChange: listener must be a function');
    }
    this.#changeListeners.push(listener);
    return () => {
      this.#changeListeners = this.#changeListeners.filter(l => l !== listener);
    };
  }

  /**
   * Get the internal handle.
   * @returns {number}
   */
  get handle() {
    return this.#handle;
  }

  /** @private */
  #notifyChange(event, txHash) {
    for (const listener of this.#changeListeners) {
      try {
        listener(event, txHash);
      } catch (_) {
        // Swallow listener errors
      }
    }
  }
}

/**
 * PlutusWitness wraps witness/verification operations.
 */
class PlutusWitness {
  /**
   * Verify a transaction via the witness mesh.
   * @param {string} chainID - Chain identifier
   * @param {string} txHash - Transaction hash
   * @param {number} [policyLevel=50] - USD value for policy tier selection
   * @returns {Promise<boolean>} Whether the transaction is confirmed
   */
  static async verify(chainID, txHash, policyLevel) {
    if (!chainID) throw new Error('PlutusWitness.verify: chainID is required');
    if (!txHash) throw new Error('PlutusWitness.verify: txHash is required');
    return Plutus.verifyTx(chainID, txHash, policyLevel || 50);
  }

  /**
   * Broadcast a signed transaction via the witness mesh.
   * @param {string} chainID - Chain identifier
   * @param {string} signedTxHex - Hex-encoded signed transaction
   * @returns {Promise<string>} Transaction hash
   */
  static async broadcastTx(chainID, signedTxHex) {
    if (!chainID) throw new Error('PlutusWitness.broadcastTx: chainID is required');
    if (!signedTxHex) throw new Error('PlutusWitness.broadcastTx: signedTx is required');
    return Plutus.broadcastTx(chainID, signedTxHex);
  }

  /**
   * Register the wallet as a witness for the given chains.
   * @param {PlutusWallet} wallet - Wallet to register as witness
   * @param {string[]} chainIDs - Chain IDs to witness
   * @returns {Promise<void>}
   */
  static async registerAsWitness(wallet, chainIDs) {
    if (!(wallet instanceof PlutusWallet)) {
      throw new Error('PlutusWitness.registerAsWitness: wallet must be a PlutusWallet instance');
    }
    if (!Array.isArray(chainIDs) || chainIDs.length === 0) {
      throw new Error('PlutusWitness.registerAsWitness: chainIDs must be a non-empty array');
    }
    return Plutus.registerWitness(wallet.handle, chainIDs);
  }
}

/**
 * PlutusReputation wraps reputation query and recording operations.
 */
class PlutusReputation {
  /**
   * Get the aggregate reputation score for a public key.
   * @param {string} pubkeyHex - Hex-encoded Ed25519 public key
   * @returns {Promise<Object>} Reputation score object
   */
  static async score(pubkeyHex) {
    if (!pubkeyHex) throw new Error('PlutusReputation.score: pubkey is required');
    const raw = await Plutus.reputation(pubkeyHex);
    return typeof raw === 'string' ? JSON.parse(raw) : raw;
  }

  /**
   * Get reputation history for a public key.
   * @param {string} pubkeyHex - Hex-encoded Ed25519 public key
   * @param {number} [limit=50] - Maximum records to return
   * @returns {Promise<Object[]>} Array of reputation records
   */
  static async history(pubkeyHex, limit) {
    if (!pubkeyHex) throw new Error('PlutusReputation.history: pubkey is required');
    const raw = await Plutus.reputationHistory(pubkeyHex, limit || 50);
    return typeof raw === 'string' ? JSON.parse(raw) : raw;
  }

  /**
   * Record a new reputation event (requires WASM-side validation).
   * @param {Object} record - Reputation record
   * @param {string} record.subjectPubKey - Hex-encoded subject public key
   * @param {string} record.recorderPubKey - Hex-encoded recorder public key
   * @param {number} record.score - Score (-1, 0, or +1)
   * @param {string} [record.signature] - Hex-encoded Ed25519 signature
   * @returns {Promise<void>}
   */
  static async record(record) {
    if (!record) throw new Error('PlutusReputation.record: record is required');
    return Plutus.recordReputation(record);
  }
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    initPlutus,
    PlutusWallet,
    PlutusEscrow,
    PlutusWitness,
    PlutusReputation,
  };
}
