const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const Web3 = require('web3');
const http = require('http');
const socketIo = require('socket.io');
const mysql = require("mysql2/promise");

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: "root",
  password: "Opeyemi1",
  database: "ucc_chain",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Load environment variables
dotenv.config();

// Create Express app
const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const RPC_WS = "ws://168.231.122.245:8546";

// Initialize Web3 with the RPC endpoint
const web3 = new Web3('http://168.231.122.245:8545');
const web3Ws = new Web3(RPC_WS);

// Create HTTP server and socket.io instance
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

web3Ws.eth.subscribe('newBlockHeaders')
  .on('connected', () => console.log('🔗 Connected to WebSocket node (Validator)'))
  .on("data", async (blockHeader) => {
    try {
      const block = await web3Ws.eth.getBlock(blockHeader.number, true);
      if (!block || block.transactions.length < 1) return;
      const timestamp = block.timestamp;

      for (const tx of block.transactions) {
        await db.query(
          `INSERT IGNORE INTO transactions 
          (hash, blockNumber, fromAddress, toAddress, value, gas, gasPrice, timestamp)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            tx.hash,
            tx.blockNumber,
            tx.from,
            tx.to,
            tx.value,
            tx.gas,
            tx.gasPrice,
            timestamp
          ]
        );
      }

      console.log(`✅ Indexed block ${block.number} (${block.transactions.length} txs)`);
    } catch (err) {
      console.error("❌ Error processing block:", err);
    }
  });

// Check if connected to the blockchain
web3.eth.net.isListening()
  .then(() => console.log('Connected to Universe Chain EVM Testnet'))
  .catch(() => console.log('Failed to connect to Universe Chain EVM Testnet'));

// Store for rate limiting
const rateLimitStore = new Map();

// Rate limiting middleware
const rateLimiter = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || 'default';
  const now = Date.now();
  const windowMs = 60000; // 1 minute
  const maxRequests = 100; // Default limit

  if (!rateLimitStore.has(apiKey)) {
    rateLimitStore.set(apiKey, {
      requests: [],
      tier: 'free' // free, basic, premium
    });
  }

  const clientInfo = rateLimitStore.get(apiKey);
  
  // Clean old requests
  clientInfo.requests = clientInfo.requests.filter(timestamp => now - timestamp < windowMs);
  
  // Check if client has exceeded limit
  if (clientInfo.requests.length >= maxRequests) {
    return res.status(429).json({ error: 'Rate limit exceeded' });
  }
  
  // Add current request
  clientInfo.requests.push(now);
  next();
};

// Routes

// Get network info
app.get('/api/network', rateLimiter, async (req, res) => {
  try {
    const [chainId, blockNumber, gasPrice] = await Promise.all([
      web3.eth.getChainId(),
      web3.eth.getBlockNumber(),
      web3.eth.getGasPrice()
    ]);
    
    res.json({
      chainId,
      blockHeight: blockNumber,
      blockTime: 5, // Average block time for POA
      gasPrice: web3.utils.fromWei(gasPrice, 'gwei') + ' Gwei',
      totalSupply: '99,999,999,999 tUCC' // As specified in requirements
    });
  } catch (error) {
    console.error('Error fetching network info:', error);
    res.status(500).json({ error: 'Failed to fetch network info' });
  }
});

// Get latest blocks
app.get('/api/blocks', rateLimiter, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    
    // Get latest block number
    const latestBlockNumber = await web3.eth.getBlockNumber();
    
    // Calculate start block
    const startBlock = latestBlockNumber - (page - 1) * limit;
    
    // Fetch blocks
    const blocks = [];
    for (let i = 0; i < limit && startBlock - i >= 0; i++) {
      const block = await web3.eth.getBlock(startBlock - i);
      if (block) {
        // Get transaction count for this block
        const transactionCount = block.transactions.length;
        
        blocks.push({
          number: block.number,
          hash: block.hash,
          timestamp: new Date(block.timestamp * 1000).toISOString(),
          transactions: transactionCount,
          gasUsed: block.gasUsed,
          gasLimit: block.gasLimit,
          miner: block.miner
        });
      }
    }
    
    res.json({
      blocks,
      totalPages: Math.ceil(latestBlockNumber / limit),
      currentPage: page
    });
  } catch (error) {
    console.error('Error fetching blocks:', error);
    res.status(500).json({ error: 'Failed to fetch blocks' });
  }
});

// Get block by number
app.get('/api/blocks/:number', rateLimiter, async (req, res) => {
  try {
    const blockNumber = req.params.number;
    const block = await web3.eth.getBlock(blockNumber);
    
    if (block) {
      // Get transaction count for this block
      const transactionCount = block.transactions.length;
      
      const blockData = {
        number: block.number,
        hash: block.hash,
        timestamp: new Date(block.timestamp * 1000).toISOString(),
        transactions: transactionCount,
        gasUsed: block.gasUsed,
        gasLimit: block.gasLimit,
        miner: block.miner,
        parentHash: block.parentHash,
        nonce: block.nonce,
        difficulty: block.difficulty,
        totalDifficulty: block.totalDifficulty,
        size: block.size,
        gasUsed: block.gasUsed,
        gasLimit: block.gasLimit,
        logsBloom: block.logsBloom,
        transactionsRoot: block.transactionsRoot,
        stateRoot: block.stateRoot,
        receiptsRoot: block.receiptsRoot,
        extraData: block.extraData
      };
      
      res.json(blockData);
    } else {
      res.status(404).json({ error: 'Block not found' });
    }
  } catch (error) {
    console.error('Error fetching block:', error);
    res.status(500).json({ error: 'Failed to fetch block' });
  }
});

// Get latest transactions
// app.get('/api/transactions', rateLimiter, async (req, res) => {
//   try {
//     const page = parseInt(req.query.page) || 1;
//     const limit = parseInt(req.query.limit) || 10;
    
//     // Get latest block number
//     const latestBlockNumber = await web3.eth.getBlockNumber();
    
//     // Fetch transactions from latest blocks
//     const transactions = [];
//     let blockNumber = latestBlockNumber;
//     let txCount = 0;
    
//     while (txCount < limit && blockNumber >= 0) {
//       const block = await web3.eth.getBlock(blockNumber, true);
      
//       if (block && block.transactions) {
//         // Add transactions from this block (in reverse order to get latest first)
//         for (let i = block.transactions.length - 1; i >= 0 && txCount < limit; i--) {
//           const tx = block.transactions[i];
//           transactions.push({
//             hash: tx.hash,
//             blockNumber: tx.blockNumber,
//             timestamp: new Date(block.timestamp * 1000).toISOString(),
//             from: tx.from,
//             to: tx.to,
//             value: web3.utils.fromWei(tx.value, 'ether') + ' tUCC',
//             gasUsed: tx.gas,
//             status: 'success' // Assuming success for simplicity
//           });
//           txCount++;
//         }
//       }
      
//       blockNumber--;
      
//       // Safety check to prevent infinite loop
//       if (latestBlockNumber - blockNumber > 100) {
//         break;
//       }
//     }
    
//     res.json({
//       transactions,
//       totalPages: Math.ceil(latestBlockNumber / limit),
//       currentPage: page
//     });
//   } catch (error) {
//     console.error('Error fetching transactions:', error);
//     res.status(500).json({ error: 'Failed to fetch transactions' });
//   }
// });

// Get transaction by hash

app.get('/api/transactions', rateLimiter, async (req, res) => {
  try {
    // Parse and validate page/limit query params
    let page = parseInt(req.query.page, 10);
    let limit = parseInt(req.query.limit, 10);

    if (isNaN(page) || page < 1) page = 1;
    if (isNaN(limit) || limit < 1 || limit > 100) limit = 10; // cap limit at 100

    const offset = (page - 1) * limit;
    const address = req.query.address;

    const transactions = [];
    let rows;

    if (address) {
      [rows] = await db.execute(
        `SELECT * FROM transactions 
         WHERE fromAddress = ? OR toAddress = ? 
         ORDER BY blockNumber DESC 
         LIMIT ${limit} OFFSET ${offset}`,
        [address, address]
      );
    } else {
      [rows] = await db.execute(
        `SELECT * FROM transactions 
         ORDER BY blockNumber DESC 
         LIMIT ${limit} OFFSET ${offset}`
      );
    }

    for (const row of rows) {
      transactions.push({
        hash: row.hash,
        blockNumber: row.blockNumber,
        timestamp: row.timestamp,
        from: row.fromAddress,
        to: row.toAddress,
        value: row.value,
        gasUsed: row.gas,
        status: 'success' // Assuming success for simplicity
      });
    }

    res.json({
      transactions,
      currentPage: page,
      pageSize: limit
    });

  } catch (error) {
    console.error("Error fetching transactions:", error);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

app.get('/api/transactions/:hash', rateLimiter, async (req, res) => {
  try {
    const transactionHash = req.params.hash;
    const transaction = await web3.eth.getTransaction(transactionHash);
    
    if (transaction) {
      // Get transaction receipt for status and gas used
      const receipt = await web3.eth.getTransactionReceipt(transactionHash);
      
      const transactionData = {
        hash: transaction.hash,
        blockNumber: transaction.blockNumber,
        timestamp: new Date().toISOString(), // We'll need to get this from the block
        from: transaction.from,
        to: transaction.to,
        value: web3.utils.fromWei(transaction.value, 'ether') + ' tUCC',
        gasUsed: receipt ? receipt.gasUsed : 0,
        gasPrice: web3.utils.fromWei(transaction.gasPrice, 'gwei') + ' Gwei',
        nonce: transaction.nonce,
        input: transaction.input,
        status: receipt ? (receipt.status ? 'success' : 'failed') : 'pending'
      };
      
      // Get timestamp from block
      if (transaction.blockNumber) {
        const block = await web3.eth.getBlock(transaction.blockNumber);
        if (block) {
          transactionData.timestamp = new Date(block.timestamp * 1000).toISOString();
        }
      }
      
      res.json(transactionData);
    } else {
      res.status(404).json({ error: 'Transaction not found' });
    }
  } catch (error) {
    console.error('Error fetching transaction:', error);
    res.status(500).json({ error: 'Failed to fetch transaction' });
  }
});

// Get tokens (mock data for now)
app.get('/api/tokens', rateLimiter, (req, res) => {
  res.json([
    {
      name: "Universe Chain Coin",
      symbol: "tUCC",
      address: "0x0000000000000000000000000000000000000000",
      price: "$1.00",
      change24h: "+2.5%",
      volume24h: "$1,234,567",
      marketCap: "$99,999,999,999"
    }
  ]);
});

// Get validators (mock data for now)
app.get('/api/validators', rateLimiter, (req, res) => {
  res.json([
    {
      name: "Validator Node 1",
      address: "0x1234567890abcdef1234567890abcdef12345678",
      status: "active",
      stake: "1,000,000 tUCC",
      blocks: 1234567,
      uptime: "99.98%"
    }
  ]);
});

// Search endpoint
// app.get('/api/search/:query', rateLimiter, async (req, res) => {
//   try {
//     const query = req.params.query.toLowerCase();
    
//     // Check if query is a block number
//     const blockNumber = parseInt(query);
//     if (!isNaN(blockNumber)) {
//       const block = await web3.eth.getBlock(blockNumber);
//       if (block) {
//         return res.json({ type: 'block', data: block });
//       }
//     }
    
//     // Check if query is a transaction hash
//     if (query.startsWith('0x') && query.length === 66) {
//       const transaction = await web3.eth.getTransaction(query);
//       if (transaction) {
//         return res.json({ type: 'transaction', data: transaction });
//       }
//     }
    
//     // Check if query is an address
//     if (query.startsWith('0x') && query.length === 42) {
//       const code = await web3.eth.getCode(query);
//       const balance = await web3.eth.getBalance(query);
//       const isContract = code !== '0x';
      
//       // Check if contract is verified (mock implementation)
//       // const isVerified = query === '0x1234567890abcdef1234567890abcdef12345678'; // Mock verified address
      
//       return res.json({ 
//         type: 'address', 
//         data: { 
//           address: query,
//           balance: web3.utils.fromWei(balance, 'ether') + ' tUCC',
//           isContract: isContract,
//           isVerified: false
//         } 
//       });
//     }
    
//     res.json({ type: 'not_found', data: null });
//   } catch (error) {
//     console.error('Error searching:', error);
//     res.status(500).json({ error: 'Search failed' });
//   }
// });

app.get('/api/search/:query', rateLimiter, async (req, res) => {
  try {
    const query = req.params.query.toLowerCase();

    // Check if query is a valid integer block number (no decimals, no scientific notation)
    if (/^\d+$/.test(query)) {
      const blockNumber = web3.utils.toBN(query); // safe conversion
      const block = await web3.eth.getBlock(blockNumber.toNumber()); 
      if (block) {
        return res.json({ type: 'block', data: block });
      }
    }

    // Check if query is a transaction hash
    if (query.startsWith('0x') && query.length === 66) {
      const transaction = await web3.eth.getTransaction(query);
      if (transaction) {
        return res.json({ type: 'transaction', data: transaction });
      }
    }

    // Check if query is an address
    if (query.startsWith('0x') && query.length === 42) {
      const code = await web3.eth.getCode(query);
      const balance = await web3.eth.getBalance(query);
      const isContract = code !== '0x';

      return res.json({ 
        type: 'address', 
        data: { 
          address: query,
          balance: web3.utils.fromWei(balance, 'ether') + ' tUCC',
          isContract,
          isVerified: false
        } 
      });
    }

    res.json({ type: 'not_found', data: null });
  } catch (error) {
    console.error('Error searching:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Get address info
app.get('/api/address/:address', rateLimiter, async (req, res) => {
  try {
    const address = req.params.address;
    
    // Validate address
    if (!web3.utils.isAddress(address)) {
      return res.status(400).json({ error: 'Invalid address' });
    }
    
    // Get balance
    const balance = await web3.eth.getBalance(address);
    
    // Get code to check if it's a contract
    const code = await web3.eth.getCode(address);
    const isContract = code !== '0x';
    
    // Get transaction count
    const txnCount = await web3.eth.getTransactionCount(address);
    
    // Check if contract is verified (mock implementation)
    const isVerified = address === '0x1234567890abcdef1234567890abcdef12345678'; // Mock verified address
    
    // Get contract info if it's a contract
    let contractInfo = null;
    if (isContract) {
      contractInfo = {
        isVerified: isVerified,
        abi: isVerified ? '[{"inputs":[],"name":"getValue","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]' : null,
        sourceCode: isVerified ? 'contract SimpleStorage { uint256 value; }' : null
      };
    }
    
    res.json({
      address: address,
      balance: web3.utils.fromWei(balance, 'ether') + ' tUCC',
      isContract: isContract,
      isVerified: isVerified,
      txnCount: txnCount,
      contractInfo: contractInfo
    });
  } catch (error) {
    console.error('Error fetching address info:', error);
    res.status(500).json({ error: 'Failed to fetch address info' });
  }
});

// Contract verification endpoint
app.post('/api/verify-contract', rateLimiter, async (req, res) => {
  try {
    const { address, sourceCode, compilerVersion, optimization } = req.body;
    
    // Validate address
    if (!web3.utils.isAddress(address)) {
      return res.status(400).json({ error: 'Invalid address' });
    }
    
    // Check if contract exists
    const code = await web3.eth.getCode(address);
    if (code === '0x') {
      return res.status(400).json({ error: 'Address is not a contract' });
    }
    
    // Mock verification process
    // In a real implementation, you would compile the source code and compare bytecode
    const verificationResult = {
      success: true,
      message: 'Contract verified successfully',
      address: address,
      compilerVersion: compilerVersion,
      optimization: optimization
    };
    
    res.json(verificationResult);
  } catch (error) {
    console.error('Error verifying contract:', error);
    res.status(500).json({ error: 'Failed to verify contract' });
  }
});

// API documentation
app.get('/api/docs', (req, res) => {
  res.json({
    name: "Universe Chain Explorer API",
    version: "1.0.0",
    description: "API for accessing Universe Chain EVM Testnet data",
    endpoints: [
      {
        method: "GET",
        path: "/api/network",
        description: "Get network information",
        rate_limit: "100 requests per minute"
      },
      {
        method: "GET",
        path: "/api/blocks",
        description: "Get latest blocks",
        rate_limit: "100 requests per minute"
      },
      {
        method: "GET",
        path: "/api/blocks/:number",
        description: "Get block by number",
        rate_limit: "100 requests per minute"
      },
      {
        method: "GET",
        path: "/api/transactions",
        description: "Get latest transactions",
        rate_limit: "100 requests per minute"
      },
      {
        method: "GET",
        path: "/api/transactions/:hash",
        description: "Get transaction by hash",
        rate_limit: "100 requests per minute"
      },
      {
        method: "GET",
        path: "/api/address/:address",
        description: "Get address information",
        rate_limit: "100 requests per minute"
      },
      {
        method: "GET",
        path: "/api/search/:query",
        description: "Search for blocks, transactions, or addresses",
        rate_limit: "100 requests per minute"
      },
      {
        method: "POST",
        path: "/api/verify-contract",
        description: "Verify a smart contract",
        rate_limit: "100 requests per minute"
      }
    ],
    rate_limiting: {
      free_tier: "100 requests per minute",
      basic_tier: "1000 requests per minute",
      premium_tier: "10000 requests per minute"
    },
    authentication: "API key required for higher rate limits"
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`Universe Chain Explorer backend running on port ${PORT}`);
  console.log(`Connecting to RPC: http://168.231.122.245:8545`);
  console.log(`Chain ID: 1366`);
  console.log(`WebSocket server running on port ${PORT}`);
});

// WebSocket connection for real-time updates
io.on('connection', (socket) => {
  console.log('New client connected');
  
  // Send initial data
  sendLatestData(socket);
  
  // Set up interval to send updates
  const interval = setInterval(() => {
    sendLatestData(socket);
  }, 5000); // Send updates every 5 seconds
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
    clearInterval(interval);
  });
});

// Function to send latest data to connected clients
async function sendLatestData(socket) {
  try {
    // Get latest block
    const latestBlockNumber = await web3.eth.getBlockNumber();
    const latestBlock = await web3.eth.getBlock(latestBlockNumber);
    
    // Get latest transactions
    const latestTransactions = [];
    const block = await web3.eth.getBlock(latestBlockNumber, true);
    if (block && block.transactions) {
      for (let i = 0; i < Math.min(5, block.transactions.length); i++) {
        const tx = block.transactions[i];
        latestTransactions.push({
          hash: tx.hash,
          blockNumber: tx.blockNumber,
          timestamp: new Date(block.timestamp * 1000).toISOString(),
          from: tx.from,
          to: tx.to,
          value: web3.utils.fromWei(tx.value, 'ether') + ' tUCC',
          gasUsed: tx.gas,
          status: 'success'
        });
      }
    }
    
    // Emit data to client
    socket.emit('latestData', {
      latestBlock: {
        number: latestBlock.number,
        hash: latestBlock.hash,
        timestamp: new Date(latestBlock.timestamp * 1000).toISOString(),
        transactions: latestBlock.transactions.length
      },
      latestTransactions: latestTransactions
    });
  } catch (error) {
    console.error('Error sending latest data:', error);
  }
}