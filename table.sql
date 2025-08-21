CREATE TABLE IF NOT EXISTS transactions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  hash VARCHAR(66) UNIQUE,
  blockNumber BIGINT,
  fromAddress VARCHAR(66),
  toAddress VARCHAR(66),
  value VARCHAR(100),
  gas VARCHAR(100),
  gasPrice VARCHAR(100),
  timestamp DATETIME
);
