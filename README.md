# Homemade Cold Wallet

## ⚠️ Disclaimer ⚠️

**Do not trust this code blindly.  
Review, audit, and verify everything yourself before using it with real funds.**

This project is for **educational and experimental purposes only**.

---

## Description

This project is a **homemade cold wallet** designed with maximum isolation in mind.

### Security Principles

- ❌ No Wi-Fi
- ❌ No Bluetooth
- ❌ No USB connection
- ✅ Fully air-gapped

The wallet operates **entirely offline** and relies on **QR codes** to interact with the outside world.

### How it works

- The device **generates QR codes** containing unsigned or signed transaction data
- It can **scan QR codes** to receive transaction information
- Transactions are **validated and signed offline**
- No direct electronic communication with any external device

This drastically reduces the attack surface compared to traditional hardware wallets.

---

## Commit Message Convention

This project follows a **conventional commit format** to keep the history clean and readable.

### Format

```

<type>(<scope>):<emoji> <subjet>

```

### Commit Convention

| Type     | Emoji | Description                                         | SemVer Impact |
|----------|-------|-----------------------------------------------------|---------------|
| Feat     | ✨     | New feature                                         | MINOR         |
| Fix      | 🐛    | Bug fix                                             | PATCH         |
| Docs     | 📚    | Documentation only changes                          | –             |
| Style    | 💎    | Formatting changes (spaces, commas, etc.)           | –             |
| Refactor | ♻️    | Code change without bug fix or new feature          | –             |
| Perf     | 🚀    | Performance improvement                             | –             |
| Test     | 🚨    | Adding or fixing tests                              | –             |
| Build    | 🛠️   | Build system or external dependency changes         | –             |
| Ci       | ⚙️    | CI configuration changes (GitHub Actions, etc.)     | –             |
| Chore    | 🔧    | Maintenance tasks (version bumps, cleanup, tooling) | –             |

---

## 🛑 Warning

This project **does not guarantee security**.

If you plan to use a cold wallet for real assets:

- Review the code carefully
- Understand the cryptography involved
- Perform your own threat modeling
- Prefer audited and battle-tested solutions for serious use

---

## License

Feel free to take my code