<div align="center">
<h1> 🔥 AReversy <br> Android app Analysis Solution</h1>
</div>

<div align="center">
    <img src="frontend/public/readmelogo.png" alt="AReversy Logo" width="150">
    <p><em>Customize, analyze and rebuild Android applications with ease</em></p>
</div>
<div align="center">
<a href="https://github.com/sd-shiivam/areversy/blob/main/LICENSE"><img src="https://img.shields.io/github/license/sd-shiivam/areversy" alt="GitHub license"></a>
<a href="https://github.com/sd-shiivam/areversy/issues"><img src="https://img.shields.io/github/issues/sd-shiivam/areversy" alt="GitHub issues"></a>
<a href="https://github.com/sd-shiivam/areversy/stargazers"><img src="https://img.shields.io/github/stars/sd-shiivam/areversy" alt="GitHub stars"></a>
<a href="https://github.com/sd-shiivam/areversy/network/members"><img src="https://img.shields.io/github/forks/sd-shiivam/areversy" alt="GitHub forks"></a>
</div>
<br>
<hr>
<br>
AReversy is a powerful web-based tool for reverse-engineering and modifying Android APK files. It provides an intuitive interface for decompiling, analyzing, modifying, and rebuilding Android applications with enhanced security features.

## ✨ Key Features

- [x] 📱 APK Decompilation and Rebuilding
- [x] 🎨 Asset and Icon Modification
- [x] 📝 AndroidManifest.xml customization
- [x] 🔐 Advanced APK Signing
- [x] 💻 Modern React UI with Material Design
- [x] 📊 Comprehensive Operation Logging
- [x] 🔍 Code Analysis Tools
- [ ] 🔒 Security Scanning

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
├── backend/            # Flask App and processing tools
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
