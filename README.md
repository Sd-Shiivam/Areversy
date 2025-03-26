# AReversy

![GitHub license](https://img.shields.io/github/license/sd-shiivam/areversy)
![GitHub issues](https://img.shields.io/github/issues/sd-shiivam/areversy)
![GitHub stars](https://img.shields.io/github/stars/sd-shiivam/areversy)
![GitHub forks](https://img.shields.io/github/forks/sd-shiivam/areversy)
![Build Status](https://github.com/sd-shiivam/areversy/workflows/Build/badge.svg)

AReversy is a powerful web-based tool for reverse-engineering and modifying Android APK files. It provides an intuitive interface for decompiling, analyzing, modifying, and rebuilding Android applications with enhanced security features.

## ✨ Key Features

- 📱 APK Decompilation and Rebuilding
- 🎨 Asset and Icon Modification
- 📝 AndroidManifest.xml Visual Editor
- 🔐 Advanced APK Signing
- 💻 Modern React UI with Material Design
- 📊 Comprehensive Operation Logging
- 🔍 Code Analysis Tools
- 🔒 Security Scanning

## 🚀 Prerequisites

- Docker & Docker Compose (v20.10+)
- Node.js v16+ (optional)
- Python 3.9+ (optional)
- Java 11+ (included in Docker)

## ⚡ Quick Start

```bash
# Clone and run
git clone https://github.com/sd-shiivam/areversy.git
cd areversy
make all
```

Access the web interface at `http://localhost:5000`

## 📁 Project Structure

```
areversy/
├── backend/             # Flask API and processing tools
│   ├── api/            # REST endpoints
│   ├── core/           # Business logic
│   └── tools/          # External utilities
├── frontend/           # React UI components
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── README.md
```

## 🛠️ Setup

1. Generate secure keystore:

```bash
keytool -genkey -v -keystore backend/tools/my-keystore.jks \
    -alias your_alias -keyalg RSA -keysize 4096 -validity 10000
```

2. Install required tools in `backend/tools/`:

   - apktool.jar (latest version)
   - apksigner.jar (latest version)

3. Launch with Docker:

```bash
make all
```

## 📱 Usage

1. Access `http://localhost:5000`
2. Upload your APK file
3. Analyze and modify components
4. Review changes
5. Download the modified APK

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) for details

## 🙏 Acknowledgments

- [apktool](https://ibotpeaches.github.io/Apktool/)
- [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer)
- [Flask](https://flask.palletsprojects.com/)
- [React](https://reactjs.org/)
- [Material-UI](https://material-ui.com/)

## ⚠️ Disclaimer

This tool is for educational purposes only. Users are responsible for complying with local laws and regulations.
