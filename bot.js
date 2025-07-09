// --- Core Modules ---
const TelegramBot = require('node-telegram-bot-api');
const { Connection, PublicKey, Keypair, VersionedTransaction, LAMPORTS_PER_SOL } = require('@solana/web3.js');
const axios = require('axios');
const bs58 = require('bs58');
const Decimal = require('decimal.js');
const fs = require('fs'); // For file system operations
const crypto = require('crypto'); // For encryption
require('dotenv').config();

// --- Local Modules ---
const SolanaTrading = require('./utils/trading.js');

// --- Bot Initialization ---
const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });
const connection = new Connection(process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com');
const solanaTrading = new SolanaTrading(connection);

// --- Wallet/Settings Storage Configuration ---
const USER_DATA_DIR = './user_data';
const ENCRYPTION_KEY_RAW = process.env.ENCRYPTION_KEY;
let ENCRYPTION_KEY_BUFFER;
try {
    if (!ENCRYPTION_KEY_RAW || ENCRYPTION_KEY_RAW.length !== 64) {
        throw new Error('ENCRYPTION_KEY must be a 64-character hex string in .env');
    }
    ENCRYPTION_KEY_BUFFER = Buffer.from(ENCRYPTION_KEY_RAW, 'hex');
} catch (e) {
    console.error('ERROR: Invalid ENCRYPTION_KEY in .env. Please set a 64-character hex string.');
    ENCRYPTION_KEY_BUFFER = crypto.createHash('sha256').update('fallback_secret_key_for_dev_only').digest();
    console.warn('Using fallback encryption key. Data is NOT secure!');
}

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;

// --- Encryption/Decryption Functions ---
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY_BUFFER, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY_BUFFER, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// --- User Data Management (File System) ---
// In-memory cache for user data (chatId -> { wallet: { publicKey, privateKey (Base58), keypair (Keypair object)}, settings: { slippageBuy: number, slippageSell: number, priorityFee: number }, transactions: [], state: string, context: object })
const cachedUserData = new Map();

async function loadUserDataFromFile(chatId) {
    const filePath = `${USER_DATA_DIR}/user_${chatId}.json`;
    console.log(`[DEBUG] Attempting to load user data from file: ${filePath}`);
    if (fs.existsSync(filePath)) {
        try {
            const encryptedData = fs.readFileSync(filePath, 'utf8');
            const decryptedData = decrypt(encryptedData);
            const userData = JSON.parse(decryptedData);

            // Reconstruct Keypair from privateKey string
            if (userData.wallet?.privateKey) {
                try {
                    userData.wallet.keypair = Keypair.fromSecretKey(bs58.decode(userData.wallet.privateKey));
                    console.log(`[DEBUG] Wallet Keypair successfully reconstructed for ${chatId}.`);
                } catch (e) {
                    console.error(`[ERROR] Failed to decode private key for user ${chatId} during load:`, e);
                    userData.wallet = null; // Invalidate wallet if decoding fails
                }
            }
            return userData;
        } catch (e) {
            console.error(`[ERROR] Error loading/decrypting user data from file for ${chatId}:`, e);
            return null;
        }
    }
    console.log(`[DEBUG] User data file not found for ${chatId}.`);
    return null;
}

async function saveUserDataToFile(chatId, userData) {
    if (!fs.existsSync(USER_DATA_DIR)) {
        fs.mkdirSync(USER_DATA_DIR, { recursive: true });
    }
    const filePath = `${USER_DATA_DIR}/user_${chatId}.json`;
    try {
        const dataToSave = { ...userData };
        if (dataToSave.wallet?.keypair) {
            dataToSave.wallet = {
                publicKey: dataToSave.wallet.publicKey,
                privateKey: dataToSave.wallet.privateKey
            };
        }
        const encryptedData = encrypt(JSON.stringify(dataToSave));
        fs.writeFileSync(filePath, encryptedData, 'utf8');
        console.log(`[DEBUG] User data saved to file for ${chatId}.`);
        return true;
    } catch (e) {
        console.error(`[ERROR] Error saving/encrypting user data for ${chatId}:`, e);
        return false;
    }
}

async function getOrCreateUserData(chatId) {
    if (cachedUserData.has(chatId)) {
        console.log(`[DEBUG] User data for ${chatId} found in cache.`);
        return cachedUserData.get(chatId);
    }

    let userData = await loadUserDataFromFile(chatId);
    if (!userData) {
        console.log(`[DEBUG] User data for ${chatId} not found in file. Creating new default data.`);
        userData = {
            wallet: null,
            settings: {
                slippageBuy: 50,
                slippageSell: 50,
                priorityFee: 0
            },
            transactions: [], // <<<--- ADDED: Array to store transaction history for PnL
            state: null,
            context: {}
        };
        await saveUserDataToFile(chatId, userData);
    } else {
        if (!userData.settings) userData.settings = {};
        if (userData.settings.slippageBuy === undefined) userData.settings.slippageBuy = 50;
        if (userData.settings.slippageSell === undefined) userData.settings.slippageSell = 50;
        if (userData.settings.priorityFee === undefined) userData.settings.priorityFee = 0;
        if (userData.context === undefined) userData.context = {};
        if (userData.state === undefined) userData.state = null;
        if (userData.transactions === undefined) userData.transactions = []; // <<<--- ADDED: Initialize if missing

        if (userData.wallet && userData.wallet.privateKey && !userData.wallet.keypair) {
            try {
                userData.wallet.keypair = Keypair.fromSecretKey(bs58.decode(userData.wallet.privateKey));
                console.log(`[DEBUG] Wallet Keypair re-constructed for user ${chatId} in getOrCreateUserData.`);
            } catch (e) {
                console.error(`[ERROR] Failed to re-construct Keypair for user ${chatId} in getOrCreateUserData:`, e);
                userData.wallet = null;
            }
        }
        console.log(`[DEBUG] User data for ${chatId} loaded from file. Wallet exists: ${!!userData.wallet}.`);
    }
    cachedUserData.set(chatId, userData);
    return userData;
}

// --- Token Data Provider (Jupiter Only) ---
class JupiterTokenDataProvider {
    constructor() {
        this.jupiterSearchURL = 'https://lite-api.jup.ag/tokens/v2/search';
    }

    async getComprehensiveTokenData(address) {
        let metadata = {
            source: 'Jupiter Search',
            address: address,
            name: 'N/A',
            symbol: 'N/A',
            decimals: null,
            logoURI: null,
            price: null,
            volume: null,
            marketCap: null,
            liquidity: null,
            fdv: null,
            verified: false,
            tags: [],
            mintAuthorityDisabled: null,
            freezeAuthorityDisabled: null,
            holderCount: null,
            launchpad: null,
            supply: null, // Ensure supply is initialized
        };

        try {
            console.log(`[DEBUG] Trying Jupiter /tokens/v2/search for ${address}...`);
            const response = await axios.get(`${this.jupiterSearchURL}?query=${address}`, {
                timeout: 10000,
                headers: { 'Accept': 'application/json' }
            });

            const data = response.data;
            if (data && data.length > 0) {
                const token = data[0];

                metadata.name = token.name ?? 'N/A';
                metadata.symbol = token.symbol ?? 'N/A';
                metadata.decimals = token.decimals ?? null;
                metadata.logoURI = token.icon ?? null;

                metadata.price = new Decimal(token.usdPrice ?? 0);
                const buyVolume = token.stats24h?.buyVolume ?? 0;
                const sellVolume = token.stats24h?.sellVolume ?? 0;
                metadata.volume = new Decimal(buyVolume + sellVolume);

                metadata.marketCap = new Decimal(token.mcap ?? 0);
                metadata.liquidity = new Decimal(token.liquidity ?? 0);
                metadata.fdv = new Decimal(token.fdv ?? 0);

                metadata.verified = token.tags?.includes('verified') || false;
                metadata.tags = token.tags || [];

                metadata.mintAuthorityDisabled = token.audit?.mintAuthorityDisabled ?? null;
                metadata.freezeAuthorityDisabled = token.audit?.freezeAuthorityDisabled ?? null;

                metadata.holderCount = token.holderCount ?? null;
                metadata.launchpad = token.launchpad ?? null;

                metadata.supply = new Decimal(token.totalSupply ?? token.circSupply ?? 0);

                console.log(`[DEBUG] Success with Jupiter Search for ${address}.`);
            } else {
                throw new Error('Token not found in Jupiter search results.');
            }
        } catch (error) {
            console.error(`[ERROR] Jupiter /tokens/v2/search failed for ${address}:`, error.message);
            if (axios.isAxiosError(error) && error.response?.status === 404) {
                 throw new Error(`Token ${address} not found on Jupiter.`);
            }
            throw new Error(`Failed to get token data from Jupiter: ${error.message}`);
        }

        if (metadata.decimals === null) {
            throw new Error('Token decimals could not be determined from Jupiter.');
        }

        return metadata;
    }
}


// --- Main Token Analysis Function ---
async function analyzeToken(contractAddress) {
    try {
        new PublicKey(contractAddress);

        const jupiterDataProvider = new JupiterTokenDataProvider();
        const metadata = await jupiterDataProvider.getComprehensiveTokenData(contractAddress);

        return {
            success: true,
            metadata: metadata,
            address: contractAddress
        };
    } catch (error) {
        console.error('[ERROR] Token analysis error:', error);
        return {
            error: error.message.includes('Invalid public key')
                ? 'Invalid contract address'
                : `Token not found or an error occurred: ${error.message}`
        };
    }
}

// --- PnL Calculation and Display Functions ---
async function calculateAndDisplayPnL(chatId, tokenAddress, messageId = null) {
    const userData = await getOrCreateUserData(chatId);
    const userTransactions = userData.transactions.filter(tx => tx.tokenAddress === tokenAddress);

    if (userTransactions.length === 0) {
        const msg = `You have no recorded transactions for token \`${tokenAddress.substring(0, 8)}...\`.`;
        if (messageId) {
            await bot.editMessageText(msg, { chat_id: chatId, message_id: messageId, parse_mode: 'Markdown' });
        } else {
            await bot.sendMessage(chatId, msg, { parse_mode: 'Markdown' });
        }
        return;
    }

    let totalAmountBought = new Decimal(0);
    let totalSolSpent = new Decimal(0);
    let totalAmountSold = new Decimal(0);
    let totalSolReceived = new Decimal(0);
    let tokenSymbol = '???';
    let tokenDecimals = 9; // Default, will be updated

    // Determine token decimals and symbol from latest transaction or Jupiter
    if (userTransactions.length > 0) {
        const lastTx = userTransactions[userTransactions.length - 1];
        tokenSymbol = lastTx.tokenSymbol || '???';
        tokenDecimals = lastTx.tokenDecimals || 9;
    }
    // Attempt to get fresh metadata for symbol and decimals
    try {
        const jupiterDataProvider = new JupiterTokenDataProvider();
        const tokenMetadata = await jupiterDataProvider.getComprehensiveTokenData(tokenAddress);
        tokenSymbol = tokenMetadata.symbol;
        tokenDecimals = tokenMetadata.decimals;
    } catch (e) {
        console.warn(`[WARN] Could not get fresh metadata for ${tokenAddress} for PnL:`, e.message);
    }


    for (const tx of userTransactions) {
        if (tx.type === 'buy') {
            totalAmountBought = totalAmountBought.plus(new Decimal(tx.tokenAmount));
            totalSolSpent = totalSolSpent.plus(new Decimal(tx.solAmount));
        } else if (tx.type === 'sell') {
            totalAmountSold = totalAmountSold.plus(new Decimal(tx.tokenAmount));
            totalSolReceived = totalSolReceived.plus(new Decimal(tx.solAmount));
        }
    }

    const currentHoldings = totalAmountBought.minus(totalAmountSold);

    if (currentHoldings.lte(0)) {
        const msg = `You no longer hold any \`${tokenSymbol}\` (\`${tokenAddress.substring(0, 8)}...\`) token. All tokens have been sold or you never bought any.`;
        if (messageId) {
            await bot.editMessageText(msg, { chat_id: chatId, message_id: messageId, parse_mode: 'Markdown' });
        } else {
            await bot.sendMessage(chatId, msg, { parse_mode: 'Markdown' });
        }
        return;
    }

    let currentTokenPriceSol = new Decimal(0);
    let currentTokenPriceUsd = new Decimal(0);

    try {
        const jupiterDataProvider = new JupiterTokenDataProvider();
        const tokenMetadata = await jupiterDataProvider.getComprehensiveTokenData(tokenAddress); // Re-fetch to be safe
        currentTokenPriceUsd = tokenMetadata.price;

        const solPriceUsd = await getSolanaPriceInUsd();
        if (currentTokenPriceUsd.gt(0) && solPriceUsd.gt(0)) {
             currentTokenPriceSol = currentTokenPriceUsd.div(solPriceUsd);
        } else {
            // Fallback for SOL price if direct USD to SOL conversion isn't possible from data
            try {
                // Get rough quote for 1 token worth of SOL if possible
                const amountForOneToken = new Decimal(1).mul(new Decimal(10).pow(tokenDecimals)); // 1 token in smallest units
                const quoteResponse = await axios.get(`https://lite-api.jup.ag/ultra/v1/quote?inputMint=${tokenAddress}&outputMint=So11111111111111111111111111111111111111112&amount=${amountForOneToken.toFixed(0)}&swapMode=ExactIn&restrictRouting=false`, { timeout: 5000 });
                if (quoteResponse.data && quoteResponse.data.outAmount) {
                     currentTokenPriceSol = new Decimal(quoteResponse.data.outAmount).div(new Decimal(10).pow(9));
                }
            } catch (quoteError) {
                console.warn(`[WARN] Could not get direct SOL quote for ${tokenAddress}:`, quoteError.message);
            }
        }
    } catch (error) {
        console.error(`[ERROR] Failed to get current price for ${tokenAddress}:`, error.message);
    }

    const netSolSpent = totalSolSpent.minus(totalSolReceived);
    let costBasisSol = new Decimal(0);
    if (currentHoldings.gt(0)) {
        costBasisSol = netSolSpent.div(currentHoldings); // Average SOL cost per token
    }


    const currentValueSol = currentHoldings.mul(currentTokenPriceSol);
    const pnlSol = currentValueSol.minus(netSolSpent);

    let pnlPercentage = new Decimal(0);
    if (netSolSpent.gt(0)) {
        pnlPercentage = pnlSol.div(netSolSpent).mul(100);
    } else if (netSolSpent.lt(0) && pnlSol.gt(0)) {
        pnlPercentage = new Decimal(100); // Atau tangani sebagai keuntungan "tak terbatas" jika biaya negatif
    } else if (netSolSpent.eq(0) && pnlSol.gt(0)) { // Misalnya token gratis
        pnlPercentage = new Decimal(100);
    }


    const solPriceUsd = await getSolanaPriceInUsd();
    const netUsdSpent = netSolSpent.mul(solPriceUsd);
    const currentValueUsd = currentHoldings.mul(currentTokenPriceUsd);
    const pnlUsd = currentValueUsd.minus(netUsdSpent);


    const message = `
📊 *PnL for ${tokenSymbol} (\`${tokenAddress.substring(0, 8)}...\`)*

*Current Holdings:* ${currentHoldings.div(new Decimal(10).pow(tokenDecimals)).toDecimalPlaces(6).toString()} ${tokenSymbol}
*Avg. Cost Basis (SOL):* ${costBasisSol.toFixed(9)} SOL/${tokenSymbol}
*Current Price (SOL):* ${currentTokenPriceSol.toFixed(9)} SOL/${tokenSymbol}
*Current Price (USD):* $${currentTokenPriceUsd.toFixed(9)} USD/${tokenSymbol}

*Net SOL Spent:* ${netSolSpent.toDecimalPlaces(6).toString()} SOL
*Current Value (SOL):* ${currentValueSol.toDecimalPlaces(6).toString()} SOL
*Profit/Loss (SOL):* ${pnlSol.toDecimalPlaces(6).toString()} SOL (${pnlPercentage.toDecimalPlaces(2).toString()}%)

*Net USD Spent:* $${netUsdSpent.toDecimalPlaces(2).toString()}
*Current Value (USD):* $${currentValueUsd.toDecimalPlaces(2).toString()}
*Profit/Loss (USD):* $${pnlUsd.toDecimalPlaces(2).toString()} (${pnlPercentage.toDecimalPlaces(2).toString()}%)
    `;

    if (messageId) {
        // Use the new PnL specific keyboard
        await bot.editMessageText(message, { chat_id: chatId, message_id: messageId, parse_mode: 'Markdown', reply_markup: createPnLTradingKeyboard(tokenAddress) });
    } else {
        // Use the new PnL specific keyboard
        await bot.sendMessage(chatId, message, { parse_mode: 'Markdown', reply_markup: createPnLTradingKeyboard(tokenAddress) });
    }
}

async function getSolanaPriceInUsd() {
    try {
        const response = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd', { timeout: 5000 });
        return new Decimal(response.data.solana.usd);
    } catch (error) {
        console.error('[ERROR] Failed to get SOL price from CoinGecko:', error.message);
        return new Decimal(0); // Return 0 if unable to fetch
    }
}

// --- Main Menu Keyboard ---
function createMainMenuKeyboard() {
    return {
        inline_keyboard: [
            [{ text: '💰 Balance', callback_data: 'show_balance' }],
            [{ text: '📊 PnL Overview', callback_data: 'show_pnl_overview' }], // <<<--- ADDED: PnL Overview
            [{ text: '⚙️ Settings', callback_data: 'show_settings' }],
            [{ text: '❓ Help', callback_data: 'show_help' }]
        ]
    };
}

// --- Settings Menu Keyboard ---
function createSettingsMenuKeyboard() {
    return {
        inline_keyboard: [
            [{ text: '👁️ View Private Key', callback_data: 'view_private_key' }],
            [{ text: '✨ Set Buy Slippage', callback_data: 'set_slippage_buy' }],
            [{ text: '✨ Set Sell Slippage', callback_data: 'set_slippage_sell' }],
            [{ text: '⚡ Set Priority Fee', callback_data: 'set_priority_fee' }],
            [{ text: '⬅️ Back to Main Menu', callback_data: 'show_main_menu' }]
        ]
    };
}

// --- Priority Fee Menu Keyboard ---
function createPriorityFeeMenuKeyboard() {
    return {
        inline_keyboard: [
            // Approximate values based on ~1.4M CU (Trojan's observed limit)
            [{ text: 'Fast (Approx. 0.005 SOL)', callback_data: 'set_priority_fee_preset_3' }], // 3 micro-lamports/CU
            [{ text: 'Beast (Approx. 0.01 SOL)', callback_data: 'set_priority_fee_preset_7' }], // 7 micro-lamports/CU
            [{ text: 'Manual Fee (micro-lamports/CU)', callback_data: 'set_priority_fee_custom' }],
            [{ text: '⬅️ Back to Settings', callback_data: 'show_settings' }]
        ]
    };
}

// --- Telegram Bot Handlers ---

// Handler for /start command
bot.onText(/\/start/, async (msg) => {
    const chatId = msg.chat.id;
    const userData = await getOrCreateUserData(chatId);
    const userWallet = userData.wallet?.keypair;

    if (userWallet) {
        bot.sendMessage(chatId, `Welcome back! Your wallet (${userWallet.publicKey.toBase58().substring(0, 8)}...) is loaded. Choose an option:`, {
            reply_markup: createMainMenuKeyboard()
        });
    } else {
        bot.sendMessage(chatId, `Welcome! You don't have a wallet yet. Please choose an option below:`, {
            reply_markup: {
                inline_keyboard: [
                    [{ text: '➕ Create New Wallet', callback_data: 'create_wallet' },
                    { text: '📥 Import Wallet (Private Key)', callback_data: 'import_wallet' }]
                ]
            }
        });
    }
});

// Handler for /help command (can also be accessed via callback)
bot.onText(/\/help/, (msg) => {
    const chatId = msg.chat.id;
    bot.sendMessage(chatId, `
I am a Solana token analysis and trading bot.
*Features:*
- Create or import your Solana wallet.
- View your wallet balance.
- Customize trading settings (e.g., slippage).
- Analyze token contracts for detailed information.
- Execute token trades (buy/sell).
- *Track PnL for your holdings.*

*How to use:*
- Send a Solana contract address directly to analyze it.
- Use /start to manage your wallet or access the main menu.
- Use /settings to configure slippage or view private key.
- Use /pnl to see your profit/loss for held tokens.
    `, { parse_mode: 'Markdown' });
});

// Handler for /settings command (can also be accessed via callback)
bot.onText(/\/settings/, async (msg) => {
    const chatId = msg.chat.id;
    const userData = await getOrCreateUserData(chatId);
    const userWallet = userData.wallet?.keypair;

    let walletInfo = "Wallet not set.";
    if (userWallet) {
        walletInfo = `Public Key: \`${userWallet.publicKey.toBase58().substring(0, 8)}...\``;
    }

    bot.sendMessage(chatId, `⚙️ *Settings*
${walletInfo}
Current Buy Slippage: ${userData.settings.slippageBuy / 100}%
Current Sell Slippage: ${userData.settings.slippageSell / 100}%
Current Priority Fee: ${userData.settings.priorityFee} micro-lamports/CU

Select an option:`, {
        parse_mode: 'Markdown',
        reply_markup: createSettingsMenuKeyboard()
    });
});

// Handler for /pnl command (new)
bot.onText(/\/pnl/, async (msg) => {
    const chatId = msg.chat.id;
    const userData = await getOrCreateUserData(chatId);
    if (!userData.wallet) {
        bot.sendMessage(chatId, 'You do not have a wallet set up. Please use /start to create or import your wallet.');
        return;
    }

    // Mendapatkan token unik dari riwayat transaksi yang mana pengguna masih memiliki kepemilikan
    const tokenHoldings = {};
    for (const tx of userData.transactions) {
        if (!tokenHoldings[tx.tokenAddress]) {
            tokenHoldings[tx.tokenAddress] = {
                bought: new Decimal(0),
                sold: new Decimal(0),
                symbol: tx.tokenSymbol,
                decimals: tx.tokenDecimals
            };
        }
        if (tx.type === 'buy') {
            tokenHoldings[tx.tokenAddress].bought = tokenHoldings[tx.tokenAddress].bought.plus(new Decimal(tx.tokenAmount));
        } else if (tx.type === 'sell') {
            tokenHoldings[tx.tokenAddress].sold = tokenHoldings[tx.tokenAddress].sold.plus(new Decimal(tx.tokenAmount));
        }
    }

    const heldTokens = Object.keys(tokenHoldings).filter(addr => tokenHoldings[addr].bought.minus(tokenHoldings[addr].sold).gt(0));

    if (heldTokens.length === 0) {
        bot.sendMessage(chatId, 'You have no recorded buy/sell transactions yet, or no tokens are currently held.');
        return;
    }

    let overviewMessage = `📊 *Your Current Holdings & PnL Overview*\n\n`;
    const keyboardButtons = [];

    for (const tokenAddress of heldTokens) {
        const holding = tokenHoldings[tokenAddress];
        let tokenSymbol = holding.symbol || '???';
        let tokenDecimals = holding.decimals || 9;

        // Coba perbarui simbol dari Jupiter untuk keakuratan
        try {
            const jupiterDataProvider = new JupiterTokenDataProvider();
            const metadata = await jupiterDataProvider.getComprehensiveTokenData(tokenAddress);
            tokenSymbol = metadata.symbol;
            tokenDecimals = metadata.decimals;
        } catch (e) {
            console.warn(`[WARN] Could not fetch fresh symbol for ${tokenAddress} for PnL overview:`, e.message);
        }

        const currentAmount = holding.bought.minus(holding.sold).div(new Decimal(10).pow(tokenDecimals));
        overviewMessage += `- \`${tokenSymbol}\` (\`${tokenAddress.substring(0, 8)}...\`): Held: ${currentAmount.toDecimalPlaces(6).toString()} ${tokenSymbol}\n`;
        keyboardButtons.push([{ text: `📈 View PnL for ${tokenSymbol}`, callback_data: `view_pnl_${tokenAddress}` }]);
    }

    bot.sendMessage(chatId, overviewMessage + '\nSelect a token to view detailed PnL:', {
        parse_mode: 'Markdown',
        reply_markup: {
            inline_keyboard: keyboardButtons
        }
    });
});


// Main message handler for direct contract address paste or state-based inputs
bot.on('message', async (msg) => {
    const chatId = msg.chat.id;
    const text = msg.text;

    // --- Immediately return if the message is a command ---
    // This allows bot.onText handlers to process commands like /start, /help, /settings, /pnl
    if (text && text.startsWith('/')) {
        return;
    }

    const userData = await getOrCreateUserData(chatId);

    // --- Handle state-based inputs first ---
    if (userData.state === 'awaiting_private_key') {
        userData.state = null; // Clear state
        try {
            const privateKey = text.trim();
            const importedKeypair = Keypair.fromSecretKey(bs58.decode(privateKey));

            userData.wallet = {
                publicKey: importedKeypair.publicKey.toBase58(),
                privateKey: bs58.encode(importedKeypair.secretKey),
                keypair: importedKeypair
            };
            const saved = await saveUserDataToFile(chatId, userData);

            if (saved) {
                bot.sendMessage(chatId, `✅ Wallet successfully imported! Your Public Key: \`${importedKeypair.publicKey.toBase58()}\`\nYour Private Key: \`${privateKey}\`\n\n*WARNING: Your private key is stored on the VPS. This is NOT recommended for high security. Please save your private key in a secure place and delete it from the chat immediately.*`, { parse_mode: 'Markdown' });
            } else {
                bot.sendMessage(chatId, '❌ Failed to save wallet. Please try again.');
            }
        } catch (error) {
            console.error('[ERROR] Error importing wallet:', error);
            bot.sendMessage(chatId, '❌ Invalid private key format or an error occurred. Please ensure it is in Base58 format.');
        } finally {
            bot.sendMessage(chatId, 'Please choose an option from the main menu:', { reply_markup: createMainMenuKeyboard() });
        }
        return;
    }

    if (userData.state === 'awaiting_slippage_buy_input') {
        userData.state = null; // Clear state
        try {
            let slippagePercentage = parseFloat(text.trim());
            if (isNaN(slippagePercentage) || slippagePercentage < 0.01 || slippagePercentage > 100) {
                throw new Error('Slippage must be a number between 0.01 and 100.');
            }
            const slippageBps = Math.round(slippagePercentage * 100);

            userData.settings.slippageBuy = slippageBps;
            const saved = await saveUserDataToFile(chatId, userData);

            if (saved) {
                bot.sendMessage(chatId, `✅ Buy Slippage successfully set to ${slippagePercentage}%.`);
            } else {
                bot.sendMessage(chatId, '❌ Failed to save buy slippage setting. Please try again.');
            }
        } catch (error) {
            console.error('[ERROR] Error setting buy slippage:', error);
            bot.sendMessage(chatId, `❌ Invalid slippage value: ${error.message}`);
        } finally {
            bot.sendMessage(chatId, 'Returning to settings menu.', { reply_markup: createSettingsMenuKeyboard() });
        }
        return;
    }

    if (userData.state === 'awaiting_slippage_sell_input') {
        userData.state = null; // Clear state
        try {
            let slippagePercentage = parseFloat(text.trim());
            if (isNaN(slippagePercentage) || slippagePercentage < 0.01 || slippagePercentage > 100) {
                throw new Error('Slippage must be a number between 0.01 and 100.');
            }
            const slippageBps = Math.round(slippagePercentage * 100);

            userData.settings.slippageSell = slippageBps;
            const saved = await saveUserDataToFile(chatId, userData);

            if (saved) {
                bot.sendMessage(chatId, `✅ Sell Slippage successfully set to ${slippagePercentage}%.`);
            } else {
                bot.sendMessage(chatId, '❌ Failed to save sell slippage setting. Please try again.');
            }
        } catch (error) {
            console.error('[ERROR] Error setting sell slippage:', error);
            bot.sendMessage(chatId, `❌ Invalid slippage value: ${error.message}`);
        } finally {
            bot.sendMessage(chatId, 'Returning to settings menu.', { reply_markup: createSettingsMenuKeyboard() });
        }
        return;
    }

    if (userData.state === 'awaiting_custom_priority_fee_input') {
        userData.state = null; // Clear state
        try {
            let customFee = parseFloat(text.trim());
            if (isNaN(customFee) || customFee < 0) {
                throw new Error('Priority fee must be a non-negative number.');
            }
            const priorityFeeBps = Math.round(customFee);

            userData.settings.priorityFee = priorityFeeBps;
            const saved = await saveUserDataToFile(chatId, userData);

            if (saved) {
                bot.sendMessage(chatId, `✅ Custom Priority Fee successfully set to ${priorityFeeBps} micro-lamports/CU.`);
            } else {
                bot.sendMessage(chatId, '❌ Failed to save priority fee setting. Please try again.');
            }
        } catch (error) {
            console.error('[ERROR] Error setting custom priority fee:', error);
            bot.sendMessage(chatId, `❌ Invalid priority fee value: ${error.message}`);
        } finally {
            bot.sendMessage(chatId, 'Returning to settings menu.', { reply_markup: createSettingsMenuKeyboard() });
        }
        return;
    }

    if (userData.state === 'awaiting_custom_sol_buy_amount') {
        userData.state = null; // Clear state
        const targetTokenAddress = userData.context.targetTokenAddress; // Retrieve the token address from context
        userData.context = {}; // Clear context
        await saveUserDataToFile(chatId, userData); // Save updated state and clear context

        if (!targetTokenAddress) {
            bot.sendMessage(chatId, '❌ Error: Target token for custom buy not found. Please try analyzing the token again.');
            return;
        }

        const userWallet = userData.wallet?.keypair;
        if (!userWallet) {
            bot.sendMessage(chatId, 'You do not have a wallet set up. Please use /start to create or import your wallet before buying.');
            return;
        }
        process.env.WALLET_PUBLIC_KEY = userWallet.publicKey.toBase58();

        let loadingMsgId;
        try {
            const solAmountInput = new Decimal(text.trim());
            if (solAmountInput.lte(0)) {
                throw new Error('Amount must be positive.');
            }

            const loadingMsg = await bot.sendMessage(chatId, `🚀 Buying ${solAmountInput.toString()} SOL worth of token for \`${targetTokenAddress.substring(0, 8)}...\`...`, { parse_mode: 'Markdown' });
            loadingMsgId = loadingMsg.message_id;

            const swapResult = await solanaTrading.executeSwap(
                { address: 'So11111111111111111111111111111111111111112', symbol: 'SOL', decimals: 9, amount: solAmountInput.toString() },
                { address: targetTokenAddress, symbol: 'UNKNOWN_TOKEN', decimals: 0 },
                userWallet,
                userData.settings.priorityFee
            );

            if (swapResult.success) {
                const tokenMetadata = await new JupiterTokenDataProvider().getComprehensiveTokenData(targetTokenAddress);
                const solSpent = new Decimal(swapResult.inputAmountResult).div(new Decimal(10).pow(9));
                const tokenDecimals = tokenMetadata.decimals || 0;
                const tokenReceived = new Decimal(swapResult.outputAmountResult).div(new Decimal(10).pow(tokenDecimals));

                userData.transactions.push({
                    type: 'buy',
                    tokenAddress: targetTokenAddress,
                    tokenSymbol: tokenMetadata.symbol || 'UNKNOWN',
                    tokenDecimals: tokenDecimals,
                    solAmount: solSpent.toNumber(),
                    tokenAmount: tokenReceived.toNumber(),
                    timestamp: new Date().toISOString()
                });
                await saveUserDataToFile(chatId, userData);

                const formattedTokenReceived = tokenReceived.toDecimalPlaces(tokenDecimals > 6 ? 6 : tokenDecimals, Decimal.ROUND_DOWN).toString(); // Format agar tidak terlalu banyak desimal
                const formattedSolSpent = solSpent.toDecimalPlaces(9).toString();

                await bot.editMessageText(
                    `✅ *Buy Successful!*
Bought ${formattedTokenReceived} ${tokenMetadata.symbol || 'UNKNOWN_TOKEN'} for ${formattedSolSpent} SOL.
Transaction: \`${swapResult.txHash}\``,
                    { chat_id: chatId, message_id: loadingMsgId, parse_mode: 'Markdown' }
                );

                // Setelah pesan sukses, tampilkan PnL dan tombol trading
                await calculateAndDisplayPnL(chatId, targetTokenAddress);

            } else {
                await bot.editMessageText(`❌ Failed to buy token: ${swapResult.error}`, { chat_id: chatId, message_id: loadingMsgId });
            }
        } catch (error) {
            console.error('[ERROR] Error processing custom SOL buy amount:', error);
            if (loadingMsgId) { // Jika ada pesan loading, edit pesan tersebut
                await bot.editMessageText(`❌ Invalid amount or an error occurred: ${error.message}`, { chat_id: chatId, message_id: loadingMsgId });
            } else { // Jika tidak ada pesan loading, kirim pesan baru
                bot.sendMessage(chatId, `❌ Invalid amount or an error occurred: ${error.message}`);
            }
        }
        return;
    }


    // --- Handle direct contract address paste ---
    if (text && text.length >= 32 && text.length <= 44) {
        console.log(`[DEBUG] Processing direct contract address: ${text}`);
        const loadingMsg = await bot.sendMessage(chatId, '🔍 Analyzing token from Jupiter...');

        try {
            const analysis = await analyzeToken(text);

            if (analysis.error) {
                bot.editMessageText(
                    `❌ Error: ${analysis.error}`,
                    { chat_id: chatId, message_id: loadingMsg.message_id }
                );
                return;
            }

            const metadata = analysis.metadata;
            const displaySupply = metadata.supply instanceof Decimal && metadata.decimals !== null ? metadata.supply.div(new Decimal(10).pow(metadata.decimals)).toDecimalPlaces(metadata.decimals > 6 ? 6 : metadata.decimals, Decimal.ROUND_DOWN).toLocaleString() : 'N/A';
            const displayPrice = metadata.price instanceof Decimal ? `$${metadata.price.toDecimalPlaces(9)}` : 'N/A';
            const displayVolume = metadata.volume instanceof Decimal ? `$${metadata.volume.toDecimalPlaces(2).toLocaleString()}` : 'N/A';
            const displayMarketCap = metadata.marketCap instanceof Decimal ? `$${metadata.marketCap.toDecimalPlaces(2).toLocaleString()}` : 'N/A';
            const displayLiquidity = metadata.liquidity instanceof Decimal ? `$${metadata.liquidity.toDecimalPlaces(2).toLocaleString()}` : 'N/A';
            const displayFDV = metadata.fdv instanceof Decimal ? `$${metadata.fdv.toDecimalPlaces(2).toLocaleString()}` : 'N/A';

            let auditInfo = '';
            if (metadata.mintAuthorityDisabled !== null) {
                auditInfo += `*Mint Disabled:* ${metadata.mintAuthorityDisabled ? '✅ Yes' : '❌ No'}\n`;
            }
            if (metadata.freezeAuthorityDisabled !== null) {
                auditInfo += `*Freeze Disabled:* ${metadata.freezeAuthorityDisabled ? '✅ Yes' : '❌ No'}\n`;
            }
            if (metadata.launchpad !== null) {
                auditInfo += `*Launchpad:* ${metadata.launchpad}\n`;
            }
            if (metadata.holderCount !== null) {
                auditInfo += `*Holders:* ${metadata.holderCount.toLocaleString()}\n`;
            }

            const message = `
🪙 *TOKEN ANALYSIS*

*Name:* ${metadata.name}
*Symbol:* ${metadata.symbol}
*Contract:* \`${analysis.address}\`
*Decimals:* ${metadata.decimals !== null ? metadata.decimals : 'N/A'}
*Data Source:* ${metadata.source}
*Price (USD):* ${displayPrice}
*24h Volume:* ${displayVolume}
*Market Cap:* ${displayMarketCap}
*Liquidity:* ${displayLiquidity}
*FDV:* ${displayFDV}
*Total Supply:* ${displaySupply}
${metadata.verified ? '✅ *Verified*' : '⚠️ *Unverified*'}
${auditInfo}
${metadata.tags && metadata.tags.length > 0 ? `*Tags:* ${metadata.tags.join(', ')}` : ''}

💰 *Ready to trade?*
            `;

            bot.editMessageText(message, {
                chat_id: chatId,
                message_id: loadingMsg.message_id,
                parse_mode: 'Markdown',
                reply_markup: createTradingKeyboard(analysis.address)
            });
        } catch (error) {
            console.error('[ERROR] Unhandled error during direct token analysis:', error);
            bot.editMessageText(
                '❌ An unexpected error occurred while analyzing the token. Please try again.',
                { chat_id: chatId, message_id: loadingMsg.message_id }
            );
        }
        return;
    }

    // Default response for non-command, non-address messages
    bot.sendMessage(chatId, 'I don\'t understand that. Please send a Solana contract address or use /start or /settings.');
});


function createTradingKeyboard(contractAddress) {
    return {
        inline_keyboard: [
            [
                { text: '🟢 Buy 0.01 SOL', callback_data: `buy_0.01_${contractAddress}` },
                { text: '🟢 Buy 0.05 SOL', callback_data: `buy_0.05_${contractAddress}` },
                { text: '🟢 Buy 0.1 SOL', callback_data: `buy_0.1_${contractAddress}` }
            ],
            [
                { text: '🟢 Buy X SOL', callback_data: `buy_x_sol_${contractAddress}` } // New button
            ],
            [
                { text: '🔴 Sell 25%', callback_data: `sell_25_${contractAddress}` },
                { text: '🔴 Sell 50%', callback_data: `sell_50_${contractAddress}` },
                { text: '🔴 Sell 100%', callback_data: `sell_100_${contractAddress}` }
            ],
            [
                { text: '🔴 Sell X Amt', callback_data: `sell_x_amount_${contractAddress}` } // New button for custom sell amount
            ],
            [
                { text: '📊 Chart (Birdeye)', url: `https://birdeye.so/token/${contractAddress}?chain=solana` },
                { text: '🔄 Refresh', callback_data: `refresh_${contractAddress}` }
            ],
            [
                { text: '📈 View PnL', callback_data: `view_pnl_${contractAddress}` }, // <<<--- ADDED: View PnL button
                { text: '✖️ Close', callback_data: 'close_menu' } // New Close button
            ]
        ]
    };
}

// NEW: Keyboard for PnL display
function createPnLTradingKeyboard(contractAddress) {
    return {
        inline_keyboard: [
            [
                { text: '🟢 Buy 0.01 SOL', callback_data: `buy_0.01_${contractAddress}` },
                { text: '🟢 Buy 0.05 SOL', callback_data: `buy_0.05_${contractAddress}` },
                { text: '🟢 Buy 0.1 SOL', callback_data: `buy_0.1_${contractAddress}` }
            ],
            [
                { text: '🟢 Buy X SOL', callback_data: `buy_x_sol_${contractAddress}` }
            ],
            [
                { text: '🔴 Sell 25%', callback_data: `sell_25_${contractAddress}` },
                { text: '🔴 Sell 50%', callback_data: `sell_50_${contractAddress}` },
                { text: '🔴 Sell 100%', callback_data: `sell_100_${contractAddress}` }
            ],
            [
                { text: '🔴 Sell X Amt', callback_data: `sell_x_amount_${contractAddress}` }
            ],
            [
                { text: '📊 Chart (Birdeye)', url: `https://birdeye.so/token/${contractAddress}?chain=solana` },
                { text: '🔄 Refresh PnL', callback_data: `refresh_pnl_${contractAddress}` } // This is for PnL refresh
            ],
            [
                { text: '✖️ Close', callback_data: 'close_menu' }
            ]
        ]
    };
}

// Callback query handler for inline buttons
bot.on('callback_query', async (callbackQuery) => {
    const message = callbackQuery.message;
    const chatId = message.chat.id;
    const data = callbackQuery.data;

    await bot.answerCallbackQuery(callbackQuery.id);

    const userData = await getOrCreateUserData(chatId);
    const userWallet = userData.wallet?.keypair;

    console.log(`[DEBUG] Callback data: ${data}, Wallet exists: ${!!userWallet}`);

    // --- Handle general navigation/settings callbacks ---
    if (data === 'create_wallet') {
        try {
            const newKeypair = Keypair.generate();
            userData.wallet = {
                publicKey: newKeypair.publicKey.toBase58(),
                privateKey: bs58.encode(newKeypair.secretKey),
                keypair: newKeypair
            };
            const saved = await saveUserDataToFile(chatId, userData);

            if (saved) {
                bot.sendMessage(chatId, `✅ New wallet successfully created!\nYour Public Key: \`${newKeypair.publicKey.toBase58()}\`\nYour Private Key: \`${bs58.encode(newKeypair.secretKey)}\`\n\n*WARNING: Your private key is stored on the VPS. This is NOT recommended for high security. Please save your private key in a secure place and delete it from the chat immediately.*`, { parse_mode: 'Markdown' });
                bot.sendMessage(chatId, 'Choose an option from the main menu:', { reply_markup: createMainMenuKeyboard() });
            } else {
                bot.sendMessage(chatId, '❌ Failed to create wallet. Please try again.');
            }
        } catch (error) {
            console.error('[ERROR] Error creating wallet:', error);
            bot.sendMessage(chatId, '❌ An error occurred while creating the wallet. Please try again.');
        }
        return;
    } else if (data === 'import_wallet') {
        userData.state = 'awaiting_private_key';
        await saveUserDataToFile(chatId, userData);
        bot.sendMessage(chatId, 'Please send your Solana wallet private key in Base58 format. \n\n*WARNING: Your private key will be stored on the VPS. This is NOT recommended for high security.*', { parse_mode: 'Markdown' });
        return;
    } else if (data === 'show_main_menu') {
        bot.sendMessage(chatId, 'Choose an option from the main menu:', { reply_markup: createMainMenuKeyboard() });
        return;
    } else if (data === 'show_settings') {
        bot.processUpdate({ message: { chat: { id: chatId }, text: '/settings' } });
        return;
    } else if (data === 'show_help') {
        bot.processUpdate({ message: { chat: { id: chatId }, text: '/help' } });
        return;
    } else if (data === 'show_balance') {
        if (!userWallet) {
            bot.sendMessage(chatId, 'You do not have a wallet set up. Please use /start to create or import your wallet.');
            return;
        }
        try {
            const solBalanceLamports = await connection.getBalance(userWallet.publicKey);
            const solBalance = solBalanceLamports / LAMPORTS_PER_SOL;

            let tokenBalancesMessage = `💰 *Your Token Balances:*\n`;
            let hasTokens = false;

            const ownedTokenAddresses = [...new Set(userData.transactions.map(tx => tx.tokenAddress))];

            for (const tokenAddress of ownedTokenAddresses) {
                try {
                    const tokenBalance = await solanaTrading.getTokenBalance(tokenAddress, userWallet.publicKey.toBase58());
                    if (tokenBalance > 0) {
                        const tokenMetadata = await new JupiterTokenDataProvider().getComprehensiveTokenData(tokenAddress);
                        tokenBalancesMessage += `- \`${tokenMetadata.symbol}\` (${tokenAddress.substring(0, 8)}...): ${tokenBalance.toFixed(6)} ${tokenMetadata.symbol}\n`;
                        hasTokens = true;
                    }
                } catch (e) {
                    console.warn(`[WARN] Could not fetch balance or metadata for token ${tokenAddress}:`, e.message);
                }
            }
            if (!hasTokens) {
                tokenBalancesMessage += `_No SPL tokens found in your wallet with recorded transactions._\n`;
            }

            bot.sendMessage(chatId, `💰 *Your Balance*\nPublic Key: \`${userWallet.publicKey.toBase58()}\`\nSOL Balance: ${solBalance.toFixed(6)} SOL\n\n${tokenBalancesMessage}`, { parse_mode: 'Markdown' });
        } catch (error) {
            console.error('[ERROR] Error fetching balance:', error);
            bot.sendMessage(chatId, '❌ Failed to fetch balance. Please try again later.');
        }
        return;
    } else if (data === 'show_pnl_overview') {
        bot.processUpdate({ message: { chat: { id: chatId }, text: '/pnl' } });
        return;
    } else if (data === 'view_private_key') {
        if (userWallet && userData.wallet?.privateKey) {
            bot.sendMessage(chatId, `🔒 Your Private Key: \`${userData.wallet.privateKey}\`\n\n*WARNING: This key grants full access to your funds. Do NOT share it with anyone. Save it in a very secure place and delete it from the chat history immediately.*`, { parse_mode: 'Markdown' });
        } else {
            bot.sendMessage(chatId, 'You do not have a wallet set up yet. Use /start to create or import one.');
        }
        return;
    } else if (data === 'set_slippage_buy') {
        userData.state = 'awaiting_slippage_buy_input';
        await saveUserDataToFile(chatId, userData);
        bot.sendMessage(chatId, `Current Buy Slippage is ${userData.settings.slippageBuy / 100}%. Please enter the new Buy slippage percentage (e.g., 0.5 for 0.5%, 1 for 1%). Min: 0.01, Max: 100.`);
        return;
    } else if (data === 'set_slippage_sell') {
        userData.state = 'awaiting_slippage_sell_input';
        await saveUserDataToFile(chatId, userData);
        bot.sendMessage(chatId, `Current Sell Slippage is ${userData.settings.slippageSell / 100}%. Please enter the new Sell slippage percentage (e.g., 0.5 for 0.5%, 1 for 1%). Min: 0.01, Max: 100.`);
        return;
    } else if (data === 'set_priority_fee') {
        bot.sendMessage(chatId, `⚡ *Set Priority Fee*
Current Fee: ${userData.settings.priorityFee} micro-lamports/CU

Choose a preset or enter a custom value:`, {
            parse_mode: 'Markdown',
            reply_markup: createPriorityFeeMenuKeyboard()
        });
        return;
    } else if (data.startsWith('set_priority_fee_preset_')) {
        const presetValue = parseInt(data.split('_')[4]);
        if (isNaN(presetValue) || presetValue < 0) {
            bot.sendMessage(chatId, '❌ Invalid preset value. Please try again.');
            return;
        }

        userData.settings.priorityFee = presetValue;
        const saved = await saveUserDataToFile(chatId, userData);

        if (saved) {
            bot.sendMessage(chatId, `✅ Priority Fee successfully set to ${presetValue} micro-lamports/CU.`);
        } else {
            bot.sendMessage(chatId, '❌ Failed to save priority fee setting. Please try again.');
        }
        bot.sendMessage(chatId, 'Returning to settings menu.', { reply_markup: createSettingsMenuKeyboard() });
        return;
    } else if (data === 'set_priority_fee_custom') {
        userData.state = 'awaiting_custom_priority_fee_input';
        await saveUserDataToFile(chatId, userData);
        bot.sendMessage(chatId, `Please enter the desired custom priority fee in micro-lamports per Compute Unit (e.g., 1, 10, 100).`);
        return;
    } else if (data.startsWith('buy_x_sol_')) {
        const parts = data.split('_');
        const targetTokenAddress = parts[3];

        if (!targetTokenAddress || targetTokenAddress.length < 32 || targetTokenAddress.length > 44) {
            console.error(`[ERROR] Invalid token address from "buy_x_sol" callback: "${targetTokenAddress}"`);
            bot.sendMessage(chatId, '❌ Error: Invalid token address in callback for custom buy. Please try analyzing the token again.');
            return;
        }

        if (!userWallet) {
            bot.sendMessage(chatId, 'You do not have a wallet set up. Please use /start to create or import your wallet before buying.');
            return;
        }

        userData.state = 'awaiting_custom_sol_buy_amount';
        userData.context.targetTokenAddress = targetTokenAddress;
        await saveUserDataToFile(chatId, userData);

        bot.sendMessage(chatId, `Please enter the amount of SOL you want to spend (e.g., 0.05, 1, 2.5) for token \`${targetTokenAddress.substring(0, 8)}...\`.`);
        return;
    } else if (data.startsWith('sell_x_amount_')) { // NEW: Handle custom "Sell X Amount" button
        const parts = data.split('_');
        const targetTokenAddress = parts[3];

        if (!targetTokenAddress || targetTokenAddress.length < 32 || targetTokenAddress.length > 44) {
            bot.sendMessage(chatId, '❌ Error: Invalid token address in callback for custom sell. Please try analyzing the token again.');
            return;
        }

        if (!userWallet) {
            bot.sendMessage(chatId, 'You do not have a wallet set up. Please use /start to create or import your wallet before selling.');
            return;
        }

        userData.state = 'awaiting_custom_token_sell_amount';
        userData.context.targetTokenAddress = targetTokenAddress;
        await saveUserDataToFile(chatId, userData);

        const tokenData = await new JupiterTokenDataProvider().getComprehensiveTokenData(targetTokenAddress);
        const currentBalance = await solanaTrading.getTokenBalance(targetTokenAddress, userWallet.publicKey.toBase58());
        bot.sendMessage(chatId, `You currently hold ${currentBalance.toDecimalPlaces(6).toString()} ${tokenData.symbol || 'tokens'}.
Please enter the amount of ${tokenData.symbol || 'token'} you want to sell (e.g., 100, 5000, 0.01) for token \`${targetTokenAddress.substring(0, 8)}...\`.`);
        return;
    } else if (userData.state === 'awaiting_custom_token_sell_amount') { // NEW: Handler for custom sell amount input
        userData.state = null; // Clear state
        const targetTokenAddress = userData.context.targetTokenAddress;
        userData.context = {}; // Clear context
        await saveUserDataToFile(chatId, userData);

        if (!targetTokenAddress) {
            bot.sendMessage(chatId, '❌ Error: Target token for custom sell not found. Please try analyzing the token again.');
            return;
        }

        const userWallet = userData.wallet?.keypair;
        if (!userWallet) {
            bot.sendMessage(chatId, 'You do not have a wallet set up. Please use /start to create or import your wallet before selling.');
            return;
        }
        process.env.WALLET_PUBLIC_KEY = userWallet.publicKey.toBase58();

        let loadingMsgId;
        try {
            const sellAmountInput = new Decimal(text.trim());
            if (sellAmountInput.lte(0)) {
                throw new Error('Amount must be positive.');
            }

            const tokenDataForSell = await new JupiterTokenDataProvider().getComprehensiveTokenData(targetTokenAddress);
            if (!tokenDataForSell || tokenDataForSell.decimals === undefined || tokenDataForSell.decimals === null) {
                throw new Error(`Failed to get token decimals for ${targetTokenAddress}.`);
            }

            const currentBalance = await solanaTrading.getTokenBalance(targetTokenAddress, userWallet.publicKey.toBase58());
            if (sellAmountInput.gt(new Decimal(currentBalance))) {
                throw new Error(`Insufficient token balance. You have ${currentBalance.toDecimalPlaces(6).toString()} ${tokenDataForSell.symbol || 'tokens'}.`);
            }

            const loadingMsg = await bot.sendMessage(chatId, `🚀 Selling ${sellAmountInput.toDecimalPlaces(6).toString()} ${tokenDataForSell.symbol || 'tokens'} for \`${targetTokenAddress.substring(0, 8)}...\`...`, { parse_mode: 'Markdown' });
            loadingMsgId = loadingMsg.message_id;

            const swapResult = await solanaTrading.executeSwap(
                { address: targetTokenAddress, symbol: tokenDataForSell.symbol, decimals: tokenDataForSell.decimals, amount: sellAmountInput.toString() },
                { address: SOL_MINT_ADDRESS, symbol: 'SOL', decimals: 9 },
                userWallet,
                userData.settings.priorityFee
            );

            if (swapResult.success) {
                const tokenSold = new Decimal(swapResult.inputAmountResult).div(new Decimal(10).pow(tokenDataForSell.decimals));
                const solReceived = new Decimal(swapResult.outputAmountResult).div(new Decimal(10).pow(9));

                userData.transactions.push({
                    type: 'sell',
                    tokenAddress: targetTokenAddress,
                    tokenSymbol: tokenDataForSell.symbol,
                    tokenDecimals: tokenDataForSell.decimals,
                    solAmount: solReceived.toNumber(),
                    tokenAmount: tokenSold.toNumber(),
                    timestamp: new Date().toISOString()
                });
                await saveUserDataToFile(chatId, userData);

                const formattedTokenSold = tokenSold.toDecimalPlaces(tokenDataForSell.decimals > 6 ? 6 : tokenDataForSell.decimals, Decimal.ROUND_DOWN).toString();
                const formattedSolReceived = solReceived.toDecimalPlaces(9).toString();

                await bot.editMessageText(
                    `✅ *Sell Successful!*
Sold ${formattedTokenSold} ${tokenDataForSell.symbol || 'UNKNOWN_TOKEN'} for ${formattedSolReceived} SOL.
Transaction: \`${swapResult.txHash}\``,
                    { chat_id: chatId, message_id: loadingMsgId, parse_mode: 'Markdown' }
                );
                await calculateAndDisplayPnL(chatId, targetTokenAddress);

            } else {
                await bot.editMessageText(`❌ Failed to sell token: ${swapResult.error}`, { chat_id: chatId, message_id: loadingMsgId });
            }
        } catch (error) {
            console.error('[ERROR] Error processing custom SOL sell amount:', error);
            if (loadingMsgId) {
                await bot.editMessageText(`❌ Invalid amount or an error occurred: ${error.message}`, { chat_id: chatId, message_id: loadingMsgId });
            } else {
                bot.sendMessage(chatId, `❌ Invalid amount or an error occurred: ${error.message}`);
            }
        }
        return;
    } else if (data.startsWith('view_pnl_')) {
        const tokenAddress = data.split('_')[2];
        const loadingMsg = await bot.sendMessage(chatId, `Calculating PnL for \`${tokenAddress.substring(0, 8)}...\`...`, { parse_mode: 'Markdown' });
        await calculateAndDisplayPnL(chatId, tokenAddress, loadingMsg.message_id);
        return;
    } else if (data.startsWith('refresh_pnl_')) { // NEW: Handle PnL Refresh button
        const tokenAddress = data.split('_')[2];
        // Edit the current message to show loading state
        await bot.editMessageText(`🔄 Refreshing PnL for \`${tokenAddress.substring(0, 8)}...\`...`, { chat_id: chatId, message_id: message.message_id, parse_mode: 'Markdown' });
        // Pass the original messageId so calculateAndDisplayPnL edits it
        await calculateAndDisplayPnL(chatId, tokenAddress, message.message_id);
        return;
    }
    else if (data === 'close_menu') { // NEW: Handle Close button
        await bot.deleteMessage(chatId, message.message_id);
        bot.sendMessage(chatId, 'Menu ditutup. Ketik `/start` atau kirim alamat kontrak untuk melanjutkan.');
        return;
    }


    // --- Handles actions requiring a wallet (fixed buys/sells, refresh) ---
    const parts = data.split('_');
    const action = parts[0];
    let contractAddress;
    let value;

    if (action === 'refresh') {
        contractAddress = parts[1];
    } else if (action === 'buy' || action === 'sell') {
        value = parts[1];
        contractAddress = parts[2];
    } else {
        console.error(`[ERROR] Unhandled callback data pattern: ${data}`);
        bot.sendMessage(chatId, '❌ An unknown action was requested. Please try again or use /start.');
        return;
    }

    if (!contractAddress || contractAddress.length < 32 || contractAddress.length > 44) {
        console.error(`[ERROR] Invalid contract address extracted from callback data: "${contractAddress}" for action "${action}"`);
        bot.sendMessage(chatId, '❌ Invalid token address in callback data. Please try analyzing the token again from scratch.');
        return;
    }
    contractAddress = contractAddress.trim();


    if (!userWallet) {
        console.warn(`[WARN] User ${chatId} attempted action ${action} without a loaded wallet.`);
        bot.sendMessage(chatId, 'You do not have a wallet set up. Please use /start to create or import your wallet before proceeding.');
        return;
    }

    const walletToUse = userWallet;
    process.env.WALLET_PUBLIC_KEY = walletToUse.publicKey.toBase58();

    const SOL_MINT_ADDRESS = 'So11111111111111111111111111111111111111112';

    let loadingMsgId = message.message_id; // Gunakan ID pesan callback untuk editing

    try {
        if (action === 'buy') {
            const solAmount = new Decimal(value);

            await bot.editMessageText(`🚀 Buying ${solAmount.toString()} SOL for token \`${contractAddress.substring(0, 8)}...\`...`, { chat_id: chatId, message_id: loadingMsgId, parse_mode: 'Markdown' });

            const swapResult = await solanaTrading.executeSwap(
                { address: SOL_MINT_ADDRESS, symbol: 'SOL', decimals: 9, amount: solAmount.toString() },
                { address: contractAddress, symbol: 'UNKNOWN_TOKEN', decimals: 0 },
                walletToUse,
                userData.settings.priorityFee
            );

            if (swapResult.success) {
                const tokenMetadata = await new JupiterTokenDataProvider().getComprehensiveTokenData(contractAddress);
                const solSpent = new Decimal(swapResult.inputAmountResult).div(new Decimal(10).pow(9));
                const tokenDecimals = tokenMetadata.decimals || 0;
                const tokenReceived = new Decimal(swapResult.outputAmountResult).div(new Decimal(10).pow(tokenDecimals));

                userData.transactions.push({
                    type: 'buy',
                    tokenAddress: contractAddress,
                    tokenSymbol: tokenMetadata.symbol || 'UNKNOWN',
                    tokenDecimals: tokenDecimals,
                    solAmount: solSpent.toNumber(),
                    tokenAmount: tokenReceived.toNumber(),
                    timestamp: new Date().toISOString()
                });
                await saveUserDataToFile(chatId, userData);

                const formattedTokenReceived = tokenReceived.toDecimalPlaces(tokenDecimals > 6 ? 6 : tokenDecimals, Decimal.ROUND_DOWN).toString();
                const formattedSolSpent = solSpent.toDecimalPlaces(9).toString();

                await bot.editMessageText(
                    `✅ *Buy Successful!*
Bought ${formattedTokenReceived} ${tokenMetadata.symbol || 'UNKNOWN_TOKEN'} for ${formattedSolSpent} SOL.
Transaction: \`${swapResult.txHash}\``,
                    { chat_id: chatId, message_id: loadingMsgId, parse_mode: 'Markdown' }
                );

                await calculateAndDisplayPnL(chatId, contractAddress);

            } else {
                await bot.editMessageText(`❌ Failed to buy token: ${swapResult.error}`, { chat_id: chatId, message_id: loadingMsgId });
            }
        } else if (action === 'sell') {
            const percent = new Decimal(value);
            const tokenBalance = await solanaTrading.getTokenBalance(contractAddress, walletToUse.publicKey.toBase58());

            if (tokenBalance === 0) {
                bot.editMessageText(`You don't have token \`${contractAddress.substring(0, 8)}...\` in your wallet.`, { chat_id: chatId, message_id: loadingMsgId, parse_mode: 'Markdown' });
                return;
            }

            const jupiterDataProvider = new JupiterTokenDataProvider();
            let tokenDataForSell = null;
            try {
                tokenDataForSell = await jupiterDataProvider.getComprehensiveTokenData(contractAddress);
            } catch (e) {
                console.error('[ERROR] Failed to get token data for sell transaction:', e);
            }

            if (!tokenDataForSell || tokenDataForSell.decimals === undefined || tokenDataForSell.decimals === null) {
                 bot.editMessageText(`Failed to get token decimals for ${contractAddress}.`, { chat_id: chatId, message_id: loadingMsgId });
                 return;
            }

            const amountToSell = new Decimal(tokenBalance).mul(percent.div(100));
            const minUnit = new Decimal(1).div(new Decimal(10).pow(tokenDataForSell.decimals));
            if (amountToSell.lt(minUnit) && amountToSell.gt(0)) {
                bot.editMessageText(`The amount (${amountToSell.toDecimalPlaces(6).toString()} ${tokenDataForSell.symbol}) is too small to sell.`, { chat_id: chatId, message_id: loadingMsgId });
                return;
            } else if (amountToSell.lte(0)) {
                bot.editMessageText(`Calculated sell amount is zero. You might not have enough token or the percentage is too small.`, { chat_id: chatId, message_id: loadingMsgId });
                return;
            }

            await bot.editMessageText(`🚀 Selling ${percent.toString()}% (${amountToSell.toDecimalPlaces(6).toString()} ${tokenDataForSell.symbol}) of \`${contractAddress.substring(0, 8)}...\`...`, { chat_id: chatId, message_id: loadingMsgId, parse_mode: 'Markdown' });

            const swapResult = await solanaTrading.executeSwap(
                { address: contractAddress, symbol: tokenDataForSell.symbol, decimals: tokenDataForSell.decimals, amount: amountToSell.toString() },
                { address: SOL_MINT_ADDRESS, symbol: 'SOL', decimals: 9 },
                walletToUse,
                userData.settings.priorityFee
            );

            if (swapResult.success) {
                const tokenSold = new Decimal(swapResult.inputAmountResult).div(new Decimal(10).pow(tokenDataForSell.decimals));
                const solReceived = new Decimal(swapResult.outputAmountResult).div(new Decimal(10).pow(9));

                userData.transactions.push({
                    type: 'sell',
                    tokenAddress: contractAddress,
                    tokenSymbol: tokenDataForSell.symbol,
                    tokenDecimals: tokenDataForSell.decimals,
                    solAmount: solReceived.toNumber(),
                    tokenAmount: tokenSold.toNumber(),
                    timestamp: new Date().toISOString()
                });
                await saveUserDataToFile(chatId, userData);

                const formattedTokenSold = tokenSold.toDecimalPlaces(tokenDataForSell.decimals > 6 ? 6 : tokenDataForSell.decimals, Decimal.ROUND_DOWN).toString();
                const formattedSolReceived = solReceived.toDecimalPlaces(9).toString();

                await bot.editMessageText(
                    `✅ *Sell Successful!*
Sold ${formattedTokenSold} ${tokenDataForSell.symbol || 'UNKNOWN_TOKEN'} for ${formattedSolReceived} SOL.
Transaction: \`${swapResult.txHash}\``,
                    { chat_id: chatId, message_id: loadingMsgId, parse_mode: 'Markdown' }
                );
                await calculateAndDisplayPnL(chatId, contractAddress);

            } else {
                await bot.editMessageText(`❌ Failed to sell token: ${swapResult.error}`, { chat_id: chatId, message_id: loadingMsgId });
            }
        } else if (action === 'refresh') {
            await bot.editMessageText('🔄 Reloading token analysis...', {
                chat_id: chatId,
                message_id: message.message_id
            });
            const analysis = await analyzeToken(contractAddress);
            if (analysis.error) {
                bot.editMessageText(
                    `❌ Error during refresh: ${analysis.error}`,
                    { chat_id: chatId, message_id: message.message_id }
                );
                return;
            }
            const metadata = analysis.metadata;
            const displaySupply = metadata.supply instanceof Decimal && metadata.decimals !== null ? metadata.supply.div(new Decimal(10).pow(metadata.decimals)).toDecimalPlaces(metadata.decimals > 6 ? 6 : metadata.decimals, Decimal.ROUND_DOWN).toLocaleString() : 'N/A';
            const displayPrice = metadata.price instanceof Decimal ? `$${metadata.price.toDecimalPlaces(9)}` : 'N/A';
            const displayVolume = metadata.volume instanceof Decimal ? `$${metadata.volume.toDecimalPlaces(2).toLocaleString()}` : 'N/A';
            const displayMarketCap = metadata.marketCap instanceof Decimal ? `$${metadata.marketCap.toDecimalPlaces(2).toLocaleString()}` : 'N/A';
            const displayLiquidity = metadata.liquidity instanceof Decimal ? `$${metadata.liquidity.toDecimalPlaces(2).toLocaleString()}` : 'N/A';
            const displayFDV = metadata.fdv instanceof Decimal ? `$${metadata.fdv.toDecimalPlaces(2).toLocaleString()}` : 'N/A';

            let auditInfo = '';
            if (metadata.mintAuthorityDisabled !== null) {
                auditInfo += `*Mint Disabled:* ${metadata.mintAuthorityDisabled ? '✅ Yes' : '❌ No'}\n`;
            }
            if (metadata.freezeAuthorityDisabled !== null) {
                auditInfo += `*Freeze Disabled:* ${metadata.freezeAuthorityDisabled ? '✅ Yes' : '❌ No'}\n`;
            }
            if (metadata.launchpad !== null) {
                auditInfo += `*Launchpad:* ${metadata.launchpad}\n`;
            }
            if (metadata.holderCount !== null) {
                auditInfo += `*Holders:* ${metadata.holderCount.toLocaleString()}\n`;
            }

            const updatedMessage = `
🪙 *TOKEN ANALYSIS* (Updated)

*Name:* ${metadata.name}
*Symbol:* ${metadata.symbol}
*Contract:* \`${analysis.address}\`
*Decimals:* ${metadata.decimals !== null ? metadata.decimals : 'N/A'}
*Data Source:* ${metadata.source}
*Price (USD):* ${displayPrice}
*24h Volume:* ${displayVolume}
*Market Cap:* ${displayMarketCap}
*Liquidity:* ${displayLiquidity}
*FDV:* ${displayFDV}
*Total Supply:* ${displaySupply}
${metadata.verified ? '✅ *Verified*' : '⚠️ *Unverified*'}
${auditInfo}
${metadata.tags && metadata.tags.length > 0 ? `*Tags:* ${metadata.tags.join(', ')}` : ''}

💰 *Ready to trade?*
            `;
            bot.editMessageText(updatedMessage, {
                chat_id: chatId,
                message_id: message.message_id,
                parse_mode: 'Markdown',
                reply_markup: createTradingKeyboard(analysis.address)
            });
        }
    } catch (error) {
        console.error('[ERROR] Callback query error:', error);
        bot.sendMessage(chatId, `❌ An error occurred while processing the request: ${error.message}`);
    }
});


console.log('🚀 Solana Universal Trading Bot with Jupiter Data started!');
